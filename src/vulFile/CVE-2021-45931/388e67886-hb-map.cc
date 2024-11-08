








hb_map_t * hb_map_create ()
{
  hb_map_t *map;

  if (!(map = hb_object_create<hb_map_t> ()))
    return hb_map_get_empty ();

  map->init_shallow ();

  return map;
}


hb_map_t * hb_map_get_empty ()
{
  return const_cast<hb_map_t *> (&Null (hb_map_t));
}


hb_map_t * hb_map_reference (hb_map_t *map)
{
  return hb_object_reference (map);
}


void hb_map_destroy (hb_map_t *map)
{
  if (!hb_object_destroy (map)) return;

  map->fini_shallow ();

  hb_free (map);
}


hb_bool_t hb_map_set_user_data (hb_map_t           *map, hb_user_data_key_t *key, void *              data, hb_destroy_func_t   destroy, hb_bool_t           replace)




{
  return hb_object_set_user_data (map, key, data, destroy, replace);
}


void * hb_map_get_user_data (hb_map_t           *map, hb_user_data_key_t *key)

{
  return hb_object_get_user_data (map, key);
}



hb_bool_t hb_map_allocation_successful (const hb_map_t  *map)
{
  return map->successful;
}



void hb_map_set (hb_map_t       *map, hb_codepoint_t  key, hb_codepoint_t  value)


{
  
  map->set (key, value);
}


hb_codepoint_t hb_map_get (const hb_map_t *map, hb_codepoint_t  key)

{
  return map->get (key);
}


void hb_map_del (hb_map_t       *map, hb_codepoint_t  key)

{
  
  map->del (key);
}


hb_bool_t hb_map_has (const hb_map_t *map, hb_codepoint_t  key)

{
  return map->has (key);
}



void hb_map_clear (hb_map_t *map)
{
  if (unlikely (hb_object_is_immutable (map)))
    return;

  return map->clear ();
}


hb_bool_t hb_map_is_empty (const hb_map_t *map)
{
  return map->is_empty ();
}


unsigned int hb_map_get_population (const hb_map_t *map)
{
  return map->get_population ();
}
