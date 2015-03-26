organization := "com.hanhuy.keepassj"

name := "keepasslibj"

libraryDependencies ++= Seq(
  "com.google.guava" % "guava" % "18.0",
  "junit" % "junit" % "4.12" % "test",
  "com.novocode" % "junit-interface" % "0.11" % "test",
  "org.bouncycastle" % "bcprov-jdk15on" % "1.52",
  "xpp3" % "xpp3" % "1.1.4c"
)