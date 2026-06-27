# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM gradle:9.0-jdk17 AS build
WORKDIR /src

COPY settings.gradle build.gradle ./
COPY src ./src
RUN --mount=type=cache,target=/home/gradle/.gradle gradle --no-daemon bootJar

FROM eclipse-temurin:17-jre-jammy AS final

ARG UID=10001
RUN useradd \
  --uid "${UID}" \
  --home-dir /nonexistent \
  --shell /usr/sbin/nologin \
  --no-create-home \
  appuser

USER appuser
WORKDIR /home/webapp

COPY --from=build /src/build/libs/private-isu-java-0.0.1-SNAPSHOT.jar /app.jar

ENTRYPOINT ["java", "-jar", "/app.jar"]
