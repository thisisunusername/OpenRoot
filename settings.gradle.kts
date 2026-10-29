// Repository order matters twice over: the first server that answers wins, and the order is also
// what CI exercises. Google's own hosts come first because that is what a GitHub runner reaches
// fastest and most reliably; Aliyun follows so a build from China still gets its mirror. When
// Aliyun was the only entry a single 502 disabled it for the whole build and every dependency
// failed to resolve, even though nothing was missing from the graph.

pluginManagement {
    repositories {
        google()
        gradlePluginPortal()
        mavenCentral()
        // Aliyun mirror
        maven {
            name = "AliyunGoogle"
            url = uri("https://maven.aliyun.com/repository/google")
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        maven {
            name = "AliyunGradlePlugin"
            url = uri("https://maven.aliyun.com/repository/gradle-plugin")
        }
        maven {
            name = "AliyunPublic"
            url = uri("https://maven.aliyun.com/repository/public")
        }
    }
}
plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        // Aliyun mirror
        maven {
            name = "AliyunGoogle"
            url = uri("https://maven.aliyun.com/repository/google")
        }
        maven {
            name = "AliyunPublic"
            url = uri("https://maven.aliyun.com/repository/public")
        }
    }
}

rootProject.name = "OpenRoot"
include(":app")
