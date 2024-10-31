import com.google.gson._;
import java.io._;
@main def exec(filePath:String, i: String){
  var jsonParser=new JsonParser();
  var jsonObject=jsonParser.parse(new FileReader(filePath));
  var list=jsonObject.getAsJsonArray;
  var cnt=0
  list.forEach(ja=>{
    var jsonObj=ja.getAsJsonObject();
    var signature=jsonObj.get("signature").getAsString();
    var line=jsonObj.get("lineNumber").getAsInt();
    var filename=jsonObj.get("filename").getAsString();
    var array1=signature.split("\\(")(0).split(" ")
    var methodName=array1(array1.length-1)
    cpg.method(methodName).filter(node=>(node.lineNumber==Some(value=line)&&node.filename==filename)).dotPdg.toJson|>"slicingJson_" + i + "/PDG"+cnt.toString+".json"
	  cpg.method(methodName).filter(node=>(node.lineNumber==Some(value=line)&&node.filename==filename)).ast.isCall.filter(node=>node.methodFullName=="<operator>.assignment").map(node=>node.lineNumber).toJson|>"slicingJson_" + i + "/assignment"+cnt.toString+".json"
	  cpg.method(methodName).filter(node=>(node.lineNumber==Some(value=line)&&node.filename==filename)).ast.isControlStructure.filter(node=>node.controlStructureType=="IF").map(node=>(node.lineNumber)).toJson|>"slicingJson_" + i + "/control"+cnt.toString+".json"
	  cpg.method(methodName).filter(node=>(node.lineNumber==Some(value=line)&&node.filename==filename)).ast.isReturn.map(node=>node.lineNumber).toJson|>"slicingJson_" + i + "/return"+cnt.toString+".json"
    cnt+=1
  })
}