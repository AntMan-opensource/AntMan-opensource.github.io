@main def exec(cveid: String)={
  cpg.method.toJson|>"metadata/method_" + cveid + ".json"
}
