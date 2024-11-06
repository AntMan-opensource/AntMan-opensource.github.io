

static void dealloc(xmlSchemaPtr schema)
{
  NOKOGIRI_DEBUG_START(schema);
  xmlSchemaFree(schema);
  NOKOGIRI_DEBUG_END(schema);
}


static VALUE validate_document(VALUE self, VALUE document)
{
  xmlDocPtr doc;
  xmlSchemaPtr schema;
  xmlSchemaValidCtxtPtr valid_ctxt;
  VALUE errors;

  Data_Get_Struct(self, xmlSchema, schema);
  Data_Get_Struct(document, xmlDoc, doc);

  errors = rb_ary_new();

  valid_ctxt = xmlSchemaNewValidCtxt(schema);

  if(NULL == valid_ctxt) {
    
    rb_raise(rb_eRuntimeError, "Could not create a validation context");
  }


  xmlSchemaSetValidStructuredErrors( valid_ctxt, Nokogiri_error_array_pusher, (void *)errors );





  xmlSchemaValidateDoc(valid_ctxt, doc);

  xmlSchemaFreeValidCtxt(valid_ctxt);

  return errors;
}


static VALUE validate_file(VALUE self, VALUE rb_filename)
{
  xmlSchemaPtr schema;
  xmlSchemaValidCtxtPtr valid_ctxt;
  const char *filename ;
  VALUE errors;

  Data_Get_Struct(self, xmlSchema, schema);
  filename = (const char*)StringValueCStr(rb_filename) ;

  errors = rb_ary_new();

  valid_ctxt = xmlSchemaNewValidCtxt(schema);

  if(NULL == valid_ctxt) {
    
    rb_raise(rb_eRuntimeError, "Could not create a validation context");
  }


  xmlSchemaSetValidStructuredErrors( valid_ctxt, Nokogiri_error_array_pusher, (void *)errors );





  xmlSchemaValidateFile(valid_ctxt, filename, 0);

  xmlSchemaFreeValidCtxt(valid_ctxt);

  return errors;
}


static VALUE read_memory(VALUE klass, VALUE content)
{
  xmlSchemaPtr schema;
  xmlSchemaParserCtxtPtr ctx = xmlSchemaNewMemParserCtxt( (const char *)StringValuePtr(content), (int)RSTRING_LEN(content)

  );
  VALUE rb_schema;
  VALUE errors = rb_ary_new();
  xmlSetStructuredErrorFunc((void *)errors, Nokogiri_error_array_pusher);


  xmlSchemaSetParserStructuredErrors( ctx, Nokogiri_error_array_pusher, (void *)errors );





   schema = xmlSchemaParse(ctx);

  xmlSetStructuredErrorFunc(NULL, NULL);
  xmlSchemaFreeParserCtxt(ctx);

  if(NULL == schema) {
    xmlErrorPtr error = xmlGetLastError();
    if(error)
      Nokogiri_error_raise(NULL, error);
    else rb_raise(rb_eRuntimeError, "Could not parse document");

    return Qnil;
  }

  rb_schema = Data_Wrap_Struct(klass, 0, dealloc, schema);
  rb_iv_set(rb_schema, "@errors", errors);

  return rb_schema;
}


static int has_blank_nodes_p(VALUE cache)
{
    long i;

    if (NIL_P(cache)) {
        return 0;
    }

    for (i = 0; i < RARRAY_LEN(cache); i++) {
        xmlNodePtr node;
        VALUE element = rb_ary_entry(cache, i);
        Data_Get_Struct(element, xmlNode, node);
        if (xmlIsBlankNode(node)) {
            return 1;
        }
    }

    return 0;
}


static VALUE from_document(VALUE klass, VALUE document)
{
  xmlDocPtr doc;
  xmlSchemaParserCtxtPtr ctx;
  xmlSchemaPtr schema;
  VALUE errors;
  VALUE rb_schema;

  Data_Get_Struct(document, xmlDoc, doc);

  
  doc = doc->doc;

  if (has_blank_nodes_p(DOC_NODE_CACHE(doc))) {
    rb_raise(rb_eArgError, "Creating a schema from a document that has blank nodes exposed to Ruby is dangerous");
  }

  ctx = xmlSchemaNewDocParserCtxt(doc);

  errors = rb_ary_new();
  xmlSetStructuredErrorFunc((void *)errors, Nokogiri_error_array_pusher);


  xmlSchemaSetParserStructuredErrors( ctx, Nokogiri_error_array_pusher, (void *)errors );





  schema = xmlSchemaParse(ctx);

  xmlSetStructuredErrorFunc(NULL, NULL);
  xmlSchemaFreeParserCtxt(ctx);

  if(NULL == schema) {
    xmlErrorPtr error = xmlGetLastError();
    if(error)
      Nokogiri_error_raise(NULL, error);
    else rb_raise(rb_eRuntimeError, "Could not parse document");

    return Qnil;
  }

  rb_schema = Data_Wrap_Struct(klass, 0, dealloc, schema);
  rb_iv_set(rb_schema, "@errors", errors);

  return rb_schema;

  return Qnil;
}

VALUE cNokogiriXmlSchema;
void init_xml_schema()
{
  VALUE nokogiri = rb_define_module("Nokogiri");
  VALUE xml = rb_define_module_under(nokogiri, "XML");
  VALUE klass = rb_define_class_under(xml, "Schema", rb_cObject);

  cNokogiriXmlSchema = klass;

  rb_define_singleton_method(klass, "read_memory", read_memory, 1);
  rb_define_singleton_method(klass, "from_document", from_document, 1);

  rb_define_private_method(klass, "validate_document", validate_document, 1);
  rb_define_private_method(klass, "validate_file",     validate_file, 1);
}
