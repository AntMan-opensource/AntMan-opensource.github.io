@main def exec(line: Int, cveid: String){
	cpg.method.filter(node=>(node.lineNumber==Some(value=line))).dotPdg.toJson|>"metadata/PDG_" + cveid + ".json"
	cpg.method.filter(node=>(node.lineNumber==Some(value=line))).ast.isCall.filter(node=>node.methodFullName=="<operator>.assignment").map(node=>node.lineNumber).toJson|>"metadata/assignment_" + cveid + ".json"
	cpg.method.filter(node=>(node.lineNumber==Some(value=line))).ast.isControlStructure.filter(node=>node.controlStructureType=="IF").map(node=>(node.lineNumber)).toJson|>"metadata/control_" + cveid + ".json"
	cpg.method.filter(node=>(node.lineNumber==Some(value=line))).ast.isReturn.map(node=>node.lineNumber).toJson|>"metadata/return_" + cveid + ".json"
}
