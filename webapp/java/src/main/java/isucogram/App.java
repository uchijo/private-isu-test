package isucogram;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementCreator;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.jdbc.support.KeyHolder;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@SpringBootApplication
public class App {
    public static void main(String[] args) {
        SpringApplication.run(App.class, args);
    }
}

@Configuration
class StaticFiles implements WebMvcConfigurer {
    @Value("${isuconp.public-dir:/home/public/}")
    private String publicDir;

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/css/**", "/js/**", "/img/**", "/favicon.ico")
                .addResourceLocations("file:" + withTrailingSlash(publicDir), "file:" + withTrailingSlash(System.getProperty("user.dir")) + "../public/");
    }

    private String withTrailingSlash(String path) {
        return path.endsWith("/") ? path : path + "/";
    }
}

@Controller
class StaticFileController {
    private final Path publicRoot;
    private final Path localPublicRoot;

    StaticFileController(@Value("${isuconp.public-dir:/home/public/}") String publicDir) {
        this.publicRoot = Path.of(publicDir).toAbsolutePath().normalize();
        this.localPublicRoot = Path.of(System.getProperty("user.dir")).resolve("../public").toAbsolutePath().normalize();
    }

    @GetMapping({"/css/{fileName:.+}", "/js/{fileName:.+}", "/img/{fileName:.+}", "/favicon.ico"})
    ResponseEntity<Resource> staticFile(HttpServletRequest request, @PathVariable(required = false) String fileName) throws IOException {
        String requestPath = request.getRequestURI();
        Path relative = Path.of(requestPath.startsWith("/") ? requestPath.substring(1) : requestPath).normalize();
        Path file = resolveStaticFile(publicRoot, relative);
        if (file == null) {
            file = resolveStaticFile(localPublicRoot, relative);
        }
        if (file == null) {
            return ResponseEntity.notFound().build();
        }

        String contentType = Files.probeContentType(file);
        if (contentType == null) {
            contentType = URLConnection.guessContentTypeFromName(file.getFileName().toString());
        }
        if (contentType == null) {
            contentType = MediaType.APPLICATION_OCTET_STREAM_VALUE;
        }
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, contentType)
                .body(new FileSystemResource(file));
    }

    private Path resolveStaticFile(Path root, Path relative) {
        Path file = root.resolve(relative).normalize();
        if (!file.startsWith(root) || !Files.isRegularFile(file)) {
            return null;
        }
        return file;
    }
}

@Controller
class IsucogramController {
    private static final int POSTS_PER_PAGE = 20;
    private static final int UPLOAD_LIMIT = 10 * 1024 * 1024;
    private static final Pattern USER_PATTERN = Pattern.compile("\\A[0-9a-zA-Z_]{3,}\\z");
    private static final Pattern PASSWORD_PATTERN = Pattern.compile("\\A[0-9a-zA-Z_]{6,}\\z");
    private static final DateTimeFormatter ISO8601 =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssXXX", Locale.ROOT);

    private final JdbcTemplate db;
    private final SecureRandom secureRandom = new SecureRandom();

    IsucogramController(JdbcTemplate db) {
        this.db = db;
    }

    @GetMapping("/initialize")
    ResponseEntity<String> initialize() {
        for (String sql : List.of(
                "DELETE FROM users WHERE id > 1000",
                "DELETE FROM posts WHERE id > 10000",
                "DELETE FROM comments WHERE id > 100000",
                "UPDATE users SET del_flg = 0",
                "UPDATE users SET del_flg = 1 WHERE id % 50 = 0")) {
            db.update(sql);
        }
        return ResponseEntity.ok("");
    }

    @GetMapping("/login")
    String getLogin(HttpSession session, Model model) {
        User me = getSessionUser(session);
        if (isLogin(me)) {
            return "redirect:/";
        }
        model.addAttribute("me", me);
        model.addAttribute("flash", getFlash(session));
        return "login";
    }

    @PostMapping("/login")
    String postLogin(
            @RequestParam("account_name") String accountName,
            @RequestParam("password") String password,
            HttpSession session) {
        if (isLogin(getSessionUser(session))) {
            return "redirect:/";
        }

        Optional<User> user = tryLogin(accountName, password);
        if (user.isPresent()) {
            session.setAttribute("user_id", user.get().id);
            session.setAttribute("csrf_token", secureRandomStr(16));
            return "redirect:/";
        }

        session.setAttribute("notice", "アカウント名かパスワードが間違っています");
        return "redirect:/login";
    }

    @GetMapping("/register")
    String getRegister(HttpSession session, Model model) {
        if (isLogin(getSessionUser(session))) {
            return "redirect:/";
        }
        model.addAttribute("me", User.empty());
        model.addAttribute("flash", getFlash(session));
        return "register";
    }

    @PostMapping("/register")
    String postRegister(
            @RequestParam("account_name") String accountName,
            @RequestParam("password") String password,
            HttpSession session) {
        if (isLogin(getSessionUser(session))) {
            return "redirect:/";
        }

        if (!validateUser(accountName, password)) {
            session.setAttribute("notice", "アカウント名は3文字以上、パスワードは6文字以上である必要があります");
            return "redirect:/register";
        }

        Integer exists = queryInteger("SELECT 1 FROM users WHERE `account_name` = ?", accountName);
        if (exists != null && exists == 1) {
            session.setAttribute("notice", "アカウント名がすでに使われています");
            return "redirect:/register";
        }

        KeyHolder keyHolder = new GeneratedKeyHolder();
        db.update(insertUser(accountName, calculatePasshash(accountName, password)), keyHolder);
        Number uid = keyHolder.getKey();
        if (uid != null) {
            session.setAttribute("user_id", uid.longValue());
            session.setAttribute("csrf_token", secureRandomStr(16));
        }
        return "redirect:/";
    }

    @GetMapping("/logout")
    String logout(HttpSession session) {
        session.invalidate();
        return "redirect:/";
    }

    @GetMapping("/")
    String index(HttpSession session, Model model) {
        List<Post> results = db.query(
                "SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` ORDER BY `created_at` DESC",
                postRowMapper(false));
        List<Post> posts = makePosts(results, getCSRFToken(session), false);
        model.addAttribute("posts", posts);
        model.addAttribute("me", getSessionUser(session));
        model.addAttribute("csrfToken", getCSRFToken(session));
        model.addAttribute("flash", getFlash(session));
        return "index";
    }

    @GetMapping("/@{accountName:[0-9a-zA-Z_]+}")
    String userPage(@PathVariable String accountName, HttpSession session, Model model, HttpServletResponse response) {
        Optional<User> userOpt = queryUser("SELECT * FROM `users` WHERE `account_name` = ? AND `del_flg` = 0", accountName);
        if (userOpt.isEmpty()) {
            response.setStatus(HttpServletResponse.SC_NOT_FOUND);
            return "empty";
        }

        User user = userOpt.get();
        List<Post> results = db.query(
                "SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` WHERE `user_id` = ? ORDER BY `created_at` DESC",
                postRowMapper(false), user.id);
        List<Post> posts = makePosts(results, getCSRFToken(session), false);
        Integer commentCount = queryInteger("SELECT COUNT(*) AS count FROM `comments` WHERE `user_id` = ?", user.id);
        List<Integer> postIDs = db.query("SELECT `id` FROM `posts` WHERE `user_id` = ?",
                (rs, rowNum) -> rs.getInt("id"), user.id);

        int commentedCount = 0;
        if (!postIDs.isEmpty()) {
            String placeholders = String.join(", ", Collections.nCopies(postIDs.size(), "?"));
            commentedCount = Optional.ofNullable(queryInteger(
                    "SELECT COUNT(*) AS count FROM `comments` WHERE `post_id` IN (" + placeholders + ")",
                    postIDs.toArray())).orElse(0);
        }

        model.addAttribute("posts", posts);
        model.addAttribute("user", user);
        model.addAttribute("postCount", postIDs.size());
        model.addAttribute("commentCount", Optional.ofNullable(commentCount).orElse(0));
        model.addAttribute("commentedCount", commentedCount);
        model.addAttribute("me", getSessionUser(session));
        return "user";
    }

    @GetMapping("/posts")
    Object posts(@RequestParam(name = "max_created_at", required = false) String maxCreatedAt,
                 HttpSession session,
                 Model model) {
        if (maxCreatedAt == null || maxCreatedAt.isEmpty()) {
            return ResponseEntity.ok("");
        }

        LocalDateTime maxTime = OffsetDateTime.parse(maxCreatedAt).atZoneSameInstant(ZoneId.systemDefault()).toLocalDateTime();
        List<Post> results = db.query(
                "SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` WHERE `created_at` <= ? ORDER BY `created_at` DESC",
                postRowMapper(false), Timestamp.valueOf(maxTime));
        List<Post> posts = makePosts(results, getCSRFToken(session), false);
        if (posts.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("");
        }
        model.addAttribute("posts", posts);
        return "posts :: posts";
    }

    @GetMapping("/posts/{id}")
    String postById(@PathVariable int id, HttpSession session, Model model, HttpServletResponse response) {
        List<Post> results = db.query("SELECT * FROM `posts` WHERE `id` = ?", postRowMapper(true), id);
        List<Post> posts = makePosts(results, getCSRFToken(session), true);
        if (posts.isEmpty()) {
            response.setStatus(HttpServletResponse.SC_NOT_FOUND);
            return "empty";
        }
        model.addAttribute("post", posts.get(0));
        model.addAttribute("me", getSessionUser(session));
        return "post_id";
    }

    @PostMapping("/")
    String createPost(@RequestParam("file") MultipartFile file,
                      @RequestParam(name = "body", defaultValue = "") String body,
                      @RequestParam(name = "csrf_token", defaultValue = "") String csrfToken,
                      HttpSession session,
                      HttpServletResponse response) throws IOException {
        User me = getSessionUser(session);
        if (!isLogin(me)) {
            return "redirect:/login";
        }

        if (!csrfToken.equals(getCSRFToken(session))) {
            response.setStatus(422);
            return "empty";
        }

        if (file == null || file.isEmpty()) {
            session.setAttribute("notice", "画像が必須です");
            return "redirect:/";
        }

        String contentType = Optional.ofNullable(file.getContentType()).orElse("");
        String mime;
        if (contentType.contains("jpeg")) {
            mime = "image/jpeg";
        } else if (contentType.contains("png")) {
            mime = "image/png";
        } else if (contentType.contains("gif")) {
            mime = "image/gif";
        } else {
            session.setAttribute("notice", "投稿できる画像形式はjpgとpngとgifだけです");
            return "redirect:/";
        }

        byte[] filedata = file.getBytes();
        if (filedata.length > UPLOAD_LIMIT) {
            session.setAttribute("notice", "ファイルサイズが大きすぎます");
            return "redirect:/";
        }

        KeyHolder keyHolder = new GeneratedKeyHolder();
        db.update(insertPost(me.id, mime, filedata, body), keyHolder);
        Number pid = keyHolder.getKey();
        return "redirect:/posts/" + (pid == null ? "" : pid.longValue());
    }

    @GetMapping("/image/{id}.{ext}")
    ResponseEntity<byte[]> image(@PathVariable int id, @PathVariable String ext) {
        Optional<Post> postOpt = queryPost("SELECT * FROM `posts` WHERE `id` = ?", id);
        if (postOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }

        Post post = postOpt.get();
        if (("jpg".equals(ext) && "image/jpeg".equals(post.mime))
                || ("png".equals(ext) && "image/png".equals(post.mime))
                || ("gif".equals(ext) && "image/gif".equals(post.mime))) {
            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_TYPE, post.mime)
                    .body(post.imgdata);
        }
        return ResponseEntity.notFound().build();
    }

    @PostMapping("/comment")
    String createComment(@RequestParam("post_id") int postID,
                         @RequestParam(name = "comment", defaultValue = "") String comment,
                         @RequestParam(name = "csrf_token", defaultValue = "") String csrfToken,
                         HttpSession session,
                         HttpServletResponse response) {
        User me = getSessionUser(session);
        if (!isLogin(me)) {
            return "redirect:/login";
        }

        if (!csrfToken.equals(getCSRFToken(session))) {
            response.setStatus(422);
            return "empty";
        }

        db.update("INSERT INTO `comments` (`post_id`, `user_id`, `comment`) VALUES (?,?,?)", postID, me.id, comment);
        return "redirect:/posts/" + postID;
    }

    @GetMapping("/admin/banned")
    String getBanned(HttpSession session, Model model, HttpServletResponse response) {
        User me = getSessionUser(session);
        if (!isLogin(me)) {
            return "redirect:/";
        }
        if (me.authority == 0) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return "empty";
        }

        List<User> users = db.query(
                "SELECT * FROM `users` WHERE `authority` = 0 AND `del_flg` = 0 ORDER BY `created_at` DESC",
                userRowMapper());
        model.addAttribute("users", users);
        model.addAttribute("me", me);
        model.addAttribute("csrfToken", getCSRFToken(session));
        return "banned";
    }

    @PostMapping("/admin/banned")
    String postBanned(@RequestParam(name = "uid[]", required = false) List<Integer> uids,
                      @RequestParam(name = "csrf_token", defaultValue = "") String csrfToken,
                      HttpSession session,
                      HttpServletResponse response) {
        User me = getSessionUser(session);
        if (!isLogin(me)) {
            return "redirect:/";
        }
        if (me.authority == 0) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return "empty";
        }
        if (!csrfToken.equals(getCSRFToken(session))) {
            response.setStatus(422);
            return "empty";
        }
        if (uids != null) {
            for (Integer uid : uids) {
                db.update("UPDATE `users` SET `del_flg` = ? WHERE `id` = ?", 1, uid);
            }
        }
        return "redirect:/admin/banned";
    }

    private Optional<User> tryLogin(String accountName, String password) {
        Optional<User> user = queryUser("SELECT * FROM users WHERE account_name = ? AND del_flg = 0", accountName);
        if (user.isPresent() && calculatePasshash(user.get().accountName, password).equals(user.get().passhash)) {
            return user;
        }
        return Optional.empty();
    }

    private boolean validateUser(String accountName, String password) {
        return USER_PATTERN.matcher(accountName).matches() && PASSWORD_PATTERN.matcher(password).matches();
    }

    private List<Post> makePosts(List<Post> results, String csrfToken, boolean allComments) {
        List<Post> posts = new ArrayList<>();
        for (Post post : results) {
            Integer count = queryInteger("SELECT COUNT(*) AS `count` FROM `comments` WHERE `post_id` = ?", post.id);
            post.commentCount = Optional.ofNullable(count).orElse(0);

            String query = "SELECT * FROM `comments` WHERE `post_id` = ? ORDER BY `created_at` DESC";
            if (!allComments) {
                query += " LIMIT 3";
            }
            List<Comment> comments = db.query(query, commentRowMapper(), post.id);
            for (Comment comment : comments) {
                comment.user = queryUser("SELECT * FROM `users` WHERE `id` = ?", comment.userId).orElse(User.empty());
            }
            Collections.reverse(comments);
            post.comments = comments;

            post.user = queryUser("SELECT * FROM `users` WHERE `id` = ?", post.userId).orElse(User.empty());
            post.csrfToken = csrfToken;

            if (post.user.delFlg == 0) {
                posts.add(post);
            }
            if (posts.size() >= POSTS_PER_PAGE) {
                break;
            }
        }
        return posts;
    }

    private User getSessionUser(HttpSession session) {
        Object uid = session.getAttribute("user_id");
        if (uid == null) {
            return User.empty();
        }
        return queryUser("SELECT * FROM `users` WHERE `id` = ?", uid).orElse(User.empty());
    }

    private String getFlash(HttpSession session) {
        Object notice = session.getAttribute("notice");
        if (notice == null) {
            return "";
        }
        session.removeAttribute("notice");
        return notice.toString();
    }

    private String getCSRFToken(HttpSession session) {
        Object token = session.getAttribute("csrf_token");
        return token == null ? "" : token.toString();
    }

    private boolean isLogin(User user) {
        return user.id != 0;
    }

    private String calculatePasshash(String accountName, String password) {
        return digest(password + ":" + digest(accountName));
    }

    private String digest(String src) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-512");
            byte[] hash = digest.digest(src.getBytes(StandardCharsets.UTF_8));
            StringBuilder builder = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                builder.append(String.format("%02x", b & 0xff));
            }
            return builder.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private String secureRandomStr(int bytes) {
        byte[] random = new byte[bytes];
        secureRandom.nextBytes(random);
        StringBuilder builder = new StringBuilder(bytes * 2);
        for (byte b : random) {
            builder.append(String.format("%02x", b & 0xff));
        }
        return builder.toString();
    }

    private Optional<User> queryUser(String sql, Object... args) {
        try {
            return Optional.ofNullable(db.queryForObject(sql, userRowMapper(), args));
        } catch (EmptyResultDataAccessException e) {
            return Optional.empty();
        }
    }

    private Optional<Post> queryPost(String sql, Object... args) {
        try {
            return Optional.ofNullable(db.queryForObject(sql, postRowMapper(true), args));
        } catch (EmptyResultDataAccessException e) {
            return Optional.empty();
        }
    }

    private Integer queryInteger(String sql, Object... args) {
        try {
            return db.queryForObject(sql, Integer.class, args);
        } catch (EmptyResultDataAccessException e) {
            return null;
        }
    }

    private PreparedStatementCreator insertUser(String accountName, String passhash) {
        return connection -> {
            PreparedStatement ps = connection.prepareStatement(
                    "INSERT INTO `users` (`account_name`, `passhash`) VALUES (?,?)",
                    Statement.RETURN_GENERATED_KEYS);
            ps.setString(1, accountName);
            ps.setString(2, passhash);
            return ps;
        };
    }

    private PreparedStatementCreator insertPost(long userID, String mime, byte[] imgdata, String body) {
        return connection -> {
            PreparedStatement ps = connection.prepareStatement(
                    "INSERT INTO `posts` (`user_id`, `mime`, `imgdata`, `body`) VALUES (?,?,?,?)",
                    Statement.RETURN_GENERATED_KEYS);
            ps.setLong(1, userID);
            ps.setString(2, mime);
            ps.setBytes(3, imgdata);
            ps.setString(4, body);
            return ps;
        };
    }

    private RowMapper<User> userRowMapper() {
        return (rs, rowNum) -> new User(
                rs.getLong("id"),
                rs.getString("account_name"),
                rs.getString("passhash"),
                rs.getInt("authority"),
                rs.getInt("del_flg"),
                readTime(rs, "created_at"));
    }

    private RowMapper<Post> postRowMapper(boolean includeImage) {
        return (rs, rowNum) -> {
            Post post = new Post();
            post.id = rs.getLong("id");
            post.userId = rs.getLong("user_id");
            post.body = rs.getString("body");
            post.mime = rs.getString("mime");
            post.createdAt = readTime(rs, "created_at");
            if (includeImage) {
                post.imgdata = rs.getBytes("imgdata");
            }
            return post;
        };
    }

    private RowMapper<Comment> commentRowMapper() {
        return (rs, rowNum) -> new Comment(
                rs.getLong("id"),
                rs.getLong("post_id"),
                rs.getLong("user_id"),
                rs.getString("comment"),
                readTime(rs, "created_at"),
                User.empty());
    }

    private LocalDateTime readTime(ResultSet rs, String column) throws SQLException {
        Timestamp ts = rs.getTimestamp(column);
        return ts == null ? null : ts.toLocalDateTime();
    }

    static class User {
        long id;
        String accountName;
        String passhash;
        int authority;
        int delFlg;
        LocalDateTime createdAt;

        User(long id, String accountName, String passhash, int authority, int delFlg, LocalDateTime createdAt) {
            this.id = id;
            this.accountName = accountName;
            this.passhash = passhash;
            this.authority = authority;
            this.delFlg = delFlg;
            this.createdAt = createdAt;
        }

        static User empty() {
            return new User(0, "", "", 0, 0, null);
        }

        public long getId() {
            return id;
        }

        public String getAccountName() {
            return accountName;
        }

        public int getAuthority() {
            return authority;
        }

        public int getDelFlg() {
            return delFlg;
        }
    }

    static class Post {
        long id;
        long userId;
        byte[] imgdata;
        String body;
        String mime;
        LocalDateTime createdAt;
        int commentCount;
        List<Comment> comments = List.of();
        User user = User.empty();
        String csrfToken = "";

        public long getId() {
            return id;
        }

        public String getBody() {
            return body;
        }

        public String getCreatedAtIso() {
            if (createdAt == null) {
                return "";
            }
            return createdAt.atZone(ZoneId.systemDefault()).format(ISO8601);
        }

        public int getCommentCount() {
            return commentCount;
        }

        public List<Comment> getComments() {
            return comments;
        }

        public User getUser() {
            return user;
        }

        public String getCsrfToken() {
            return csrfToken;
        }

        public String getImageUrl() {
            String ext = "";
            if ("image/jpeg".equals(mime)) {
                ext = ".jpg";
            } else if ("image/png".equals(mime)) {
                ext = ".png";
            } else if ("image/gif".equals(mime)) {
                ext = ".gif";
            }
            return "/image/" + id + ext;
        }
    }

    static class Comment {
        long id;
        long postId;
        long userId;
        String comment;
        LocalDateTime createdAt;
        User user;

        Comment(long id, long postId, long userId, String comment, LocalDateTime createdAt, User user) {
            this.id = id;
            this.postId = postId;
            this.userId = userId;
            this.comment = comment;
            this.createdAt = createdAt;
            this.user = user;
        }

        public String getComment() {
            return comment;
        }

        public User getUser() {
            return user;
        }
    }
}
