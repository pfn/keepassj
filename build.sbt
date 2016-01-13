organization := "com.hanhuy.keepassj"

name := "keepassj"

version := "2.31.0"

crossPaths := false

autoScalaLibrary := false

javacOptions in (Compile,compile) ++= Seq("-source", "1.7", "-target", "1.7")

libraryDependencies ++= Seq(
  "com.google.guava" % "guava" % "18.0",
  "junit" % "junit" % "4.12" % "test",
  "org.hamcrest" % "hamcrest-all" % "1.3" % "test",
  "com.novocode" % "junit-interface" % "0.11" % "test",
  "org.bouncycastle" % "bcprov-jdk15on" % "1.52",
  "xpp3" % "xpp3" % "1.1.4c"
)

// sonatype publishing options follow
publishMavenStyle := true

publishTo := {
  val nexus = "https://oss.sonatype.org/"
  if (isSnapshot.value)
    Some("snapshots" at nexus + "content/repositories/snapshots")
  else
    Some("releases"  at nexus + "service/local/staging/deploy/maven2")
}

pomIncludeRepository := { _ => false }

pomExtra :=
  <scm>
    <url>git@github.com:pfn/keepassj.git</url>
    <connection>scm:git:git@github.com:pfn/keepassj.git</connection>
  </scm>
  <developers>
    <developer>
      <id>pfnguyen</id>
      <name>Perry Nguyen</name>
      <url>https://github.com/pfn</url>
    </developer>
  </developers>

licenses := Seq("GPL, v2" -> url("https://www.gnu.org/licenses/gpl-2.0.html"))

homepage := Some(url("https://github.com/pfn/keepassj"))
