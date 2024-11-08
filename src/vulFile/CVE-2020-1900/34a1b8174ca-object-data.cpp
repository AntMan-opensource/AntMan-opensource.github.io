








































namespace HPHP {



TRACE_SET_MOD(runtime);



namespace {

const StaticString s_clone("__clone");

ALWAYS_INLINE void verifyTypeHint(const Class* thisCls, const Class::Prop* prop, tv_lval val) {


  assertx(tvIsPlausible(*val));
  assertx(type(val) != KindOfUninit);
  if (!prop || RuntimeOption::EvalCheckPropTypeHints <= 0) return;
  if (prop->typeConstraint.isCheckable()) {
    prop->typeConstraint.verifyProperty(val, thisCls, prop->cls, prop->name);
  }
  if (RuntimeOption::EvalEnforceGenericsUB <= 0) return;
  for (auto const& ub : prop->ubs) {
    if (ub.isCheckable()) {
      ub.verifyProperty(val, thisCls, prop->cls, prop->name);
    }
  }
}

ALWAYS_INLINE void unsetTypeHint(const Class::Prop* prop) {
  if (RuntimeOption::EvalCheckPropTypeHints <= 0) return;
  if (!prop || prop->typeConstraint.isMixedResolved()) return;
  raise_property_typehint_unset_error( prop->cls, prop->name, prop->typeConstraint.isSoft(), prop->typeConstraint.isUpperBound()



  );
}

}




namespace {
bool assertATypeHint(const TypeConstraint& tc, tv_rval val) {
  if (!tc.isCheckable() || tc.isSoft()) return true;
  if (val.type() == KindOfUninit) return tc.maybeMixed();
  return tc.assertCheck(val);
}
}

bool ObjectData::assertTypeHint(tv_rval prop, Slot slot) const {
  assertx(tvIsPlausible(*prop));
  assertx(slot < m_cls->numDeclProperties());
  auto const& propDecl = m_cls->declProperties()[slot];

  if (debug && RuntimeOption::RepoAuthoritative) {
    
    
    if (prop.type() != KindOfUninit || !(propDecl.attrs & AttrLateInit)) {
      always_assert(tvMatchesRepoAuthType(*prop, propDecl.repoAuthType));
    }
  }

  
  if (RuntimeOption::EvalCheckPropTypeHints <= 2) return true;
  if (!propDecl.typeConstraint.isCheckable() || propDecl.typeConstraint.isSoft()) return true;
  if (propDecl.typeConstraint.isUpperBound() && RuntimeOption::EvalEnforceGenericsUB < 2) return true;
  if (prop.type() == KindOfNull && !(propDecl.attrs & AttrNoImplicitNullable)) {
    return true;
  }
  if (prop.type() == KindOfUninit && (propDecl.attrs & AttrLateInit)) {
    return true;
  }
  assertATypeHint(propDecl.typeConstraint, prop);
  if (RuntimeOption::EvalEnforceGenericsUB <= 2) return true;
  for (auto const& ub : propDecl.ubs) {
    if (!assertATypeHint(ub, prop)) return false;
  }
  return true;
}



NEVER_INLINE static void freeDynPropArray(ObjectData* inst) {
  auto& table = g_context->dynPropTable;
  auto it = table.find(inst);
  assertx(it != end(table));
  assertx(it->second.arr().isPHPArray());
  it->second.destroy();
  table.erase(it);
}

NEVER_INLINE void ObjectData::slowDestroyCases() {
  assertx(slowDestroyCheck());

  if (getAttribute(UsedMemoCache)) {
    assertx(m_cls->hasMemoSlots());
    auto const nSlots = m_cls->numMemoSlots();
    for (Slot i = 0; i < nSlots; ++i) {
      auto slot = memoSlot(i);
      if (slot->isCache()) {
        if (auto cache = slot->getCache()) req::destroy_raw(cache);
      } else {
        tvDecRefGen(*slot->getValue());
      }
    }
  }

  if (UNLIKELY(getAttribute(HasDynPropArr))) freeDynPropArray(this);
  if (UNLIKELY(getAttribute(IsWeakRefed))) {
    WeakRefData::invalidateWeakRef((uintptr_t)this);
  }

  auto const memoSize = m_cls->memoSize();
  auto const ptr = reinterpret_cast<char*>(this) - memoSize;
  tl_heap->objFreeIndex(ptr, m_cls->sizeIdx());
}


inline bool ObjectData::slowDestroyCheck() const {
  return m_aux16 & (HasDynPropArr | IsWeakRefed | UsedMemoCache | BigAllocSize);
}

void ObjectData::release(ObjectData* obj, const Class* cls) noexcept {
  assertx(obj->kindIsValid());
  assertx(!obj->hasInstanceDtor());
  assertx(!obj->hasNativeData());
  assertx(obj->getVMClass() == cls);
  assertx(cls->releaseFunc() == &ObjectData::release);
  assertx(obj->props()->checkInvariants(cls->numDeclProperties()));

  
  
  
  
  
  
  
  
  
  
  
  

  
  

  obj->props()->release(cls->countablePropsEnd());

  if (UNLIKELY(obj->slowDestroyCheck())) {
    obj->slowDestroyCases();
  } else {
    assertx((obj->m_aux16 & BigAllocSize) == 0);
    auto const memoSize = cls->memoSize();
    auto const ptr = reinterpret_cast<char*>(obj) - memoSize;
    assertx(memoSize == 0 || reinterpret_cast<const MemoNode*>(ptr)->objOff() == memoSize);

    tl_heap->freeSmallIndex(ptr, cls->sizeIdx());
  }

  AARCH64_WALKABLE_FRAME();
}




StrNR ObjectData::getClassName() const {
  return m_cls->preClass()->nameStr();
}

bool ObjectData::instanceof(const String& s) const {
  assertx(kindIsValid());
  auto const cls = Unit::lookupClass(s.get());
  return cls && instanceof(cls);
}

bool ObjectData::toBooleanImpl() const noexcept {
  
  
  if (isCollection()) {
    if (RuntimeOption::EvalNoticeOnCollectionToBool) {
      raise_notice( "%s to boolean cast", collections::typeToString((CollectionType)m_kind)->data()

      );
    }
    return collections::toBool(this);
  }

  if (instanceof(SimpleXMLElement_classof())) {
    
    
    if (RuntimeOption::EvalNoticeOnSimpleXMLBehavior) {
      raise_notice("SimpleXMLElement to boolean cast");
    }
    return SimpleXMLElement_objectCast(this, KindOfBoolean).toBoolean();
  }

  always_assert(false);
  return false;
}

int64_t ObjectData::toInt64Impl() const noexcept {
  
  assertx(instanceof(SimpleXMLElement_classof()));
  if (RuntimeOption::EvalNoticeOnSimpleXMLBehavior) {
    raise_notice("SimpleXMLElement to integer cast");
  }
  return SimpleXMLElement_objectCast(this, KindOfInt64).toInt64();
}

double ObjectData::toDoubleImpl() const noexcept {
  
  assertx(instanceof(SimpleXMLElement_classof()));
  if (RuntimeOption::EvalNoticeOnSimpleXMLBehavior) {
    raise_notice("SimpleXMLElement to double cast");
  }
  return SimpleXMLElement_objectCast(this, KindOfDouble).toDouble();
}




const StaticString s_getIterator("getIterator");

Object ObjectData::iterableObject(bool& isIterable, bool mayImplementIterator ) {
  assertx(mayImplementIterator || !isIterator());
  if (mayImplementIterator && isIterator()) {
    isIterable = true;
    return Object(this);
  }
  Object obj(this);
  while (obj->instanceof(SystemLib::s_IteratorAggregateClass)) {
    auto iterator = obj->o_invoke_few_args(s_getIterator, 0);
    if (!iterator.isObject()) break;
    auto o = iterator.getObjectData();
    if (o->isIterator()) {
      isIterable = true;
      return Object{o};
    }
    obj.reset(o);
  }
  if (!isIterator() && obj->instanceof(SimpleXMLElement_classof())) {
    if (RuntimeOption::EvalNoticeOnSimpleXMLBehavior) {
      raise_notice("SimpleXMLElement used as iterator");
    }
    isIterable = true;
    return create_object( s_SimpleXMLElementIterator, make_vec_array(obj)

    );
  }
  isIterable = false;
  return obj;
}

Array& ObjectData::dynPropArray() const {
  assertx(getAttribute(HasDynPropArr));
  assertx(g_context->dynPropTable.count(this));
  assertx(g_context->dynPropTable[this].arr().isPHPArray());
  return g_context->dynPropTable[this].arr();
}

void ObjectData::setDynProps(const Array& newArr) {
  
  (void)setDynPropArray(newArr);
}

void ObjectData::reserveDynProps(int numDynamic) {
  
  (void)reserveProperties(numDynamic);
}

Array& ObjectData::reserveProperties(int numDynamic ) {
  if (getAttribute(HasDynPropArr)) {
    return dynPropArray();
  }

  return setDynPropArray( Array::attach(MixedArray::MakeReserveMixed(numDynamic))
  );
}

Array& ObjectData::setDynPropArray(const Array& newArr) {
  assertx(!g_context->dynPropTable.count(this));
  assertx(!getAttribute(HasDynPropArr));
  assertx(newArr.isPHPArray());

  if (m_cls->forbidsDynamicProps()) {
    throw_object_forbids_dynamic_props(getClassName().data());
  }
  if (RuntimeOption::EvalNoticeOnCreateDynamicProp) {
    IterateKV(newArr.get(), [&] (TypedValue k, TypedValue v) {
      auto const key = tvCastToString(k);
      raiseCreateDynamicProp(key.get());
    });
  }

  
  auto& arr = g_context->dynPropTable[this].arr();
  assertx(arr.isPHPArray());
  arr = newArr;
  setAttribute(HasDynPropArr);
  return arr;
}

tv_lval ObjectData::makeDynProp(const StringData* key) {
  if (RuntimeOption::EvalNoticeOnCreateDynamicProp) {
    raiseCreateDynamicProp(key);
  }
  return reserveProperties().lvalForce(StrNR(key), AccessFlags::Key);
}

void ObjectData::setDynProp(const StringData* key, TypedValue val) {
  if (RuntimeOption::EvalNoticeOnCreateDynamicProp) {
    raiseCreateDynamicProp(key);
  }
  reserveProperties().set(StrNR(key), val, true);
}

Variant ObjectData::o_get(const String& propName, bool error , const String& context ) {
  assertx(kindIsValid());

  
  
  if (UNLIKELY(!*propName.data())) {
    throw_invalid_property_name(propName);
  }

  Class* ctx = nullptr;
  if (!context.empty()) {
    ctx = Unit::lookupClass(context.get());
  }

  
  
  

  auto const lookup = getPropImpl<false, true, true>(ctx, propName.get());
  if (lookup.val && lookup.accessible) {
    if (lookup.val.type() != KindOfUninit) {
      return Variant::wrap(lookup.val.tv());
    } else if (lookup.prop && (lookup.prop->attrs & AttrLateInit)) {
      if (error) throw_late_init_prop(lookup.prop->cls, propName.get(), false);
      return uninit_null();
    }
  }

  if (error) {
    raise_notice("Undefined property: %s::$%s", getClassName().data(), propName.data());
  }

  return uninit_null();
}

void ObjectData::o_set(const String& propName, const Variant& v, const String& context ) {
  assertx(kindIsValid());

  
  
  if (UNLIKELY(!*propName.data())) {
    throw_invalid_property_name(propName);
  }

  Class* ctx = nullptr;
  if (!context.empty()) {
    ctx = Unit::lookupClass(context.get());
  }

  
  
  

  auto const lookup = getPropImpl<true, false, true>(ctx, propName.get());
  auto prop = lookup.val;
  if (prop && lookup.accessible) {
    if (UNLIKELY(lookup.isConst) && !isBeingConstructed()) {
      throwMutateConstProp(lookup.slot);
    }
    auto val = tvToInit(*v.asTypedValue());
    verifyTypeHint(m_cls, lookup.prop, &val);
    tvSet(val, prop);
    return;
  }

  if (!prop) {
    setDynProp(propName.get(), tvToInit(*v.asTypedValue()));
  }
}

void ObjectData::o_setArray(const Array& properties) {
  for (ArrayIter iter(properties); iter; ++iter) {
    String k = iter.first().toString();
    Class* ctx = nullptr;
    
    
    
    
    
    if (!k.empty() && k[0] == '\0') {
      int subLen = k.find('\0', 1) + 1;
      String cls = k.substr(1, subLen - 2);
      if (cls.size() == 1 && cls[0] == '*') {
        
        ctx = m_cls;
      } else {
        
        ctx = Unit::lookupClass(cls.get());
        if (!ctx) continue;
      }
      k = k.substr(subLen);
    }

    setProp(ctx, k.get(), tvAssertPlausible(iter.secondVal()));
  }
}

void ObjectData::o_getArray(Array& props, bool pubOnly , bool ignoreLateInit ) const {

  assertx(kindIsValid());

  
  if (!m_cls->numDeclProperties() && getAttribute(HasDynPropArr)) {
    props = dynPropArray();
    if (RuntimeOption::EvalNoticeOnReadDynamicProp) {
      IterateKV(props.get(), [&](TypedValue k, TypedValue) {
        auto const key = tvCastToString(k);
        raiseReadDynamicProp(key.get());
      });
    }
    return;
  }

  auto cls = m_cls;
  if (cls->hasReifiedGenerics()) {
    auto const slot = cls->lookupReifiedInitProp();
    assertx(slot != kInvalidSlot);
    auto const declProps = cls->declProperties();
    auto const prop = declProps[slot];
    auto val = this->propRvalAtOffset(slot);
    props.set(StrNR(prop.name).asString(), val.tv());
  }
  IteratePropToArrayOrderNoInc( this, [&](Slot slot, const Class::Prop& prop, tv_rval val) {

      assertx(assertTypeHint(val, slot));
      if (UNLIKELY(val.type() == KindOfUninit)) {
        if (!ignoreLateInit && (prop.attrs & AttrLateInit)) {
          throw_late_init_prop(prop.cls, prop.name, false);
        }
      } else if (!pubOnly || (prop.attrs & AttrPublic)) {
        
        
        if (prop.name != s_86reified_prop.get()) {
          props.set(StrNR(prop.mangledName).asString(), val.tv());
        }
      }
    }, [&](TypedValue key_tv, TypedValue val) {
      props.set(key_tv, val, true);
      if (RuntimeOption::EvalNoticeOnReadDynamicProp) {
        auto const key = tvCastToString(key_tv);
        raiseReadDynamicProp(key.get());
      }
    }
  );
}



const int64_t ARRAY_OBJ_ITERATOR_STD_PROP_LIST = 1;

const StaticString s_flags("flags"), s_storage("storage");

template <IntishCast IC > Array ObjectData::toArray(bool pubOnly , bool ignoreLateInit ) const {

  assertx(kindIsValid());

  
  
  if (isCollection()) {
    return collections::toArray<IC>(this);
  } else if (UNLIKELY(m_cls->rtAttribute(Class::CallToImpl))) {
    
    
    assertx(instanceof(SimpleXMLElement_classof()));
    if (RuntimeOption::EvalNoticeOnSimpleXMLBehavior) {
      raise_notice("SimpleXMLElement to array cast");
    }
    return SimpleXMLElement_objectCast(this, KindOfArray).toArray();
  } else if (UNLIKELY(instanceof(SystemLib::s_ArrayIteratorClass))) {
    auto const flags = getProp(SystemLib::s_ArrayIteratorClass, s_flags.get());
    assertx(flags.is_set());
    if (UNLIKELY(flags.type() == KindOfInt64 && flags.val().num == ARRAY_OBJ_ITERATOR_STD_PROP_LIST)) {
      auto ret = Array::CreateDArray();
      o_getArray(ret, true, ignoreLateInit);
      return ret;
    }

    check_recursion_throw();

    auto const storage = getProp(SystemLib::s_ArrayIteratorClass, s_storage.get());
    assertx(storage.is_set());
    return tvCastToArrayLike(storage.tv());
  } else if (UNLIKELY(instanceof(c_Closure::classof()))) {
    return make_varray(Object(const_cast<ObjectData*>(this)));
  } else if (UNLIKELY(instanceof(DateTimeData::getClass()))) {
    return Native::data<DateTimeData>(this)->getDebugInfo();
  } else {
    auto ret = Array::CreateDArray();
    o_getArray(ret, pubOnly, ignoreLateInit);
    return ret;
  }
}

template Array ObjectData::toArray<IntishCast::None>(bool, bool) const;
template Array ObjectData::toArray<IntishCast::Cast>(bool, bool) const;


namespace {

size_t getPropertyIfAccessible(ObjectData* obj, const Class* ctx, const StringData* key, Array& properties, size_t propLeft) {



  auto const prop = obj->getProp(ctx, key);
  if (prop && prop.type() != KindOfUninit) {
    --propLeft;
    properties.set(StrNR(key), prop.tv(), true);
  }
  return propLeft;
}

}

Array ObjectData::o_toIterArray(const String& context) {
  if (!m_cls->numDeclProperties()) {
    if (getAttribute(HasDynPropArr)) {
      auto const props = dynPropArray();
      if (RuntimeOption::EvalNoticeOnReadDynamicProp) {
        IterateKV(props.get(), [&](TypedValue k, TypedValue) {
          auto const key = tvCastToString(k);
          raiseReadDynamicProp(key.get());
        });
      }
      
      return props;
    }
    return Array::CreateDArray();
  }

  size_t accessibleProps = m_cls->declPropNumAccessible();
  size_t size = accessibleProps;
  if (getAttribute(HasDynPropArr)) {
    size += dynPropArray().size();
  }
  Array retArray { Array::attach(MixedArray::MakeReserveMixed(size)) };

  Class* ctx = nullptr;
  if (!context.empty()) {
    ctx = Unit::lookupClass(context.get());
  }

  
  
  const Class* klass = m_cls;
  while (klass) {
    const PreClass::Prop* props = klass->preClass()->properties();
    const size_t numProps = klass->preClass()->numProperties();

    for (size_t i = 0; i < numProps; ++i) {
      auto key = const_cast<StringData*>(props[i].name());
      accessibleProps = getPropertyIfAccessible( this, ctx, key, retArray, accessibleProps);
    }
    klass = klass->parent();
  }
  if (!(m_cls->attrs() & AttrNoExpandTrait) && accessibleProps > 0) {
    
    for (auto const& prop : m_cls->declProperties()) {
      auto const key = prop.name.get();
      if (!retArray.get()->exists(key)) {
        accessibleProps = getPropertyIfAccessible( this, ctx, key, retArray, accessibleProps);
        if (accessibleProps == 0) break;
      }
    }
  }

  
  if (getAttribute(HasDynPropArr)) {
    auto& dynProps = dynPropArray();
    auto ad = dynProps.get();
    ssize_t iter = ad->iter_begin();
    auto pos_limit = ad->iter_end();
    while (iter != pos_limit) {
      ad = dynProps.get();
      auto const key = ad->nvGetKey(iter);
      iter = ad->iter_advance(iter);

      if (RuntimeOption::EvalNoticeOnReadDynamicProp) {
        auto const k = tvCastToString(key);
        raiseReadDynamicProp(k.get());
      }

      
      
      
      if (UNLIKELY(!isStringType(key.m_type))) {
        assertx(key.m_type == KindOfInt64);
        auto const val = dynProps.get()->at(key.m_data.num);
        retArray.set(key.m_data.num, val);
        continue;
      }

      auto const strKey = key.m_data.pstr;
      auto const val = dynProps.get()->at(strKey);
      retArray.set(StrNR(strKey), val, true );
    }
  }

  return retArray;
}

static bool decode_invoke(const String& s, ObjectData* obj, bool fatal, CallCtx& ctx) {
  ctx.this_ = obj;
  ctx.cls = obj->getVMClass();
  ctx.dynamic = true;

  ctx.func = ctx.cls->lookupMethod(s.get());
  if (!ctx.func) {
    
    o_invoke_failed(ctx.cls->name()->data(), s.data(), fatal);
    return false;
  }

  
  if (ctx.func->isStaticInPrologue()) {
    ctx.this_ = nullptr;
  }
  return true;
}

Variant ObjectData::o_invoke(const String& s, const Variant& params, bool fatal ) {
  CallCtx ctx;
  if (!decode_invoke(s, this, fatal, ctx) || (!isContainer(params) && !params.isNull())) {
    return Variant(Variant::NullInit());
  }
  return Variant::attach( g_context->invokeFunc(ctx, params)
  );
}








Variant ObjectData::o_invoke_few_args(const String& s, int count, INVOKE_FEW_ARGS_IMPL_ARGS) {

  CallCtx ctx;
  if (!decode_invoke(s, this, true, ctx)) {
    return Variant(Variant::NullInit());
  }

  TypedValue args[INVOKE_FEW_ARGS_COUNT];
  switch(count) {
    default: not_implemented();

    case 10: tvCopy(*a9.asTypedValue(), args[9]);
    case  9: tvCopy(*a8.asTypedValue(), args[8]);
    case  8: tvCopy(*a7.asTypedValue(), args[7]);
    case  7: tvCopy(*a6.asTypedValue(), args[6]);


    case  6: tvCopy(*a5.asTypedValue(), args[5]);
    case  5: tvCopy(*a4.asTypedValue(), args[4]);
    case  4: tvCopy(*a3.asTypedValue(), args[3]);

    case  3: tvCopy(*a2.asTypedValue(), args[2]);
    case  2: tvCopy(*a1.asTypedValue(), args[1]);
    case  1: tvCopy(*a0.asTypedValue(), args[0]);
    case  0: break;
  }

  return Variant::attach( g_context->invokeFuncFew(ctx, count, args)
  );
}

ObjectData* ObjectData::clone() {
  if (isCppBuiltin()) {
    assertx(!m_cls->hasMemoSlots());
    if (isCollection()) return collections::clone(this);
    if (instanceof(c_Closure::classof())) {
      return c_Closure::fromObject(this)->clone();
    }
    assertx(instanceof(c_Awaitable::classof()));
    
    
    auto const ctor = m_cls->instanceCtor();
    ctor(m_cls);
    always_assert(false);
  }

  
  Object clone;
  auto const nProps = m_cls->numDeclProperties();
  if (hasNativeData()) {
    assertx(m_cls->instanceDtor() == Native::nativeDataInstanceDtor);
    clone = Object::attach( Native::nativeDataInstanceCopyCtor(this, m_cls, nProps)
    );
    assertx(clone->hasExactlyOneRef());
    assertx(clone->hasInstanceDtor());
  } else {
    auto const alloc = allocMemoInit(m_cls);

    auto const obj = new (NotNull{}, alloc.mem)
                     ObjectData(m_cls, InitRaw{}, alloc.flags);
    clone = Object::attach(obj);
    assertx(clone->hasExactlyOneRef());
    assertx(!clone->hasInstanceDtor());
  }

  auto const cloneProps = clone->props();
  cloneProps->init(m_cls->numDeclProperties());
  for (auto slot = Slot{0}; slot < nProps; slot++) {
    auto index = m_cls->propSlotToIndex(slot);
    tvDup(*props()->at(index), cloneProps->at(index));
    assertx(assertTypeHint(cloneProps->at(index), slot));
  }

  if (UNLIKELY(getAttribute(HasDynPropArr))) {
    clone->setAttribute(HasDynPropArr);
    g_context->dynPropTable.emplace(clone.get(), dynPropArray().get());
  }
  if (m_cls->rtAttribute(Class::HasClone)) {
    assertx(!isCppBuiltin());
    auto const method = clone->m_cls->lookupMethod(s_clone.get());
    assertx(method);
    clone->unlockObject();
    SCOPE_EXIT { clone->lockObject(); };
    g_context->invokeMethodV(clone.get(), method, InvokeArgs{}, false);
  }
  return clone.detach();
}

bool ObjectData::equal(const ObjectData& other) const {
  if (this == &other) return true;
  if (isCollection()) {
    return collections::equals(this, &other);
  }
  if (UNLIKELY(instanceof(SystemLib::s_DateTimeInterfaceClass) && other.instanceof(SystemLib::s_DateTimeInterfaceClass))) {
    return DateTimeData::compare(this, &other) == 0;
  }
  if (getVMClass() != other.getVMClass()) return false;
  if (UNLIKELY(instanceof(SimpleXMLElement_classof()))) {
    if (RuntimeOption::EvalNoticeOnSimpleXMLBehavior) {
      raise_notice("SimpleXMLElement equality comparison");
    }
    
    auto ar1 = SimpleXMLElement_objectCast(this, KindOfArray).toArray();
    auto ar2 = SimpleXMLElement_objectCast(&other, KindOfArray).toArray();
    return ArrayData::Equal(ar1.get(), ar2.get());
  }
  if (UNLIKELY(instanceof(c_Closure::classof()))) {
    
    return false;
  }

  
  
  auto thisSize = UNLIKELY(getAttribute(HasDynPropArr)) ? dynPropArray().size() : 0;
  size_t otherSize = 0;
  ArrayData* otherDynProps = nullptr;
  if (UNLIKELY(other.getAttribute(HasDynPropArr))) {
    otherDynProps = other.dynPropArray().get();
    otherSize = otherDynProps->size();
  }
  if (thisSize != otherSize) return false;

  
  check_recursion_error();

  bool result = true;
  IteratePropMemOrderNoInc( this, [&](Slot slot, const Class::Prop& prop, tv_rval thisVal) {

      auto otherVal = other.propRvalAtOffset(slot);
      if ((UNLIKELY(thisVal.type() == KindOfUninit) || UNLIKELY(otherVal.type() == KindOfUninit)) && (prop.attrs & AttrLateInit)) {

        throw_late_init_prop(prop.cls, prop.name, false);
      }
      if (!tvEqual(thisVal.tv(), otherVal.tv())) {
        result = false;
        return true;
      }
      return false;
    }, [&](TypedValue key, TypedValue thisVal) {
      auto const otherVal = otherDynProps->get(key);
      if (!otherVal.is_init() || !tvEqual(thisVal, otherVal)) {
        result = false;
        return true;
      }
      return false;
    }
  );
  return result;
}

bool ObjectData::less(const ObjectData& other) const {
  
  return compare(other) < 0;
}

bool ObjectData::lessEqual(const ObjectData& other) const {
  
  return compare(other) <= 0;
}

bool ObjectData::more(const ObjectData& other) const {
  
  return other.compare(*this) < 0;
}

bool ObjectData::moreEqual(const ObjectData& other) const {
  
  return other.compare(*this) <= 0;
}

int64_t ObjectData::compare(const ObjectData& other) const {
  if (isCollection() || other.isCollection()) {
    throw_collection_compare_exception();
  }
  if (this == &other) return 0;
  if (UNLIKELY(instanceof(SystemLib::s_DateTimeInterfaceClass) && other.instanceof(SystemLib::s_DateTimeInterfaceClass))) {
    return DateTimeData::compare(this, &other);
  }
  
  if (getVMClass() != other.getVMClass()) return 1;
  if (UNLIKELY(instanceof(SimpleXMLElement_classof()))) {
    if (RuntimeOption::EvalNoticeOnSimpleXMLBehavior) {
      raise_notice("SimpleXMLElement comparison");
    }
    
    auto ar1 = SimpleXMLElement_objectCast(this, KindOfArray).toArray();
    auto ar2 = SimpleXMLElement_objectCast(&other, KindOfArray).toArray();
    return ArrayData::Compare(ar1.get(), ar2.get());
  }
  if (UNLIKELY(instanceof(c_Closure::classof()))) {
    
    return 1;
  }

  
  
  auto thisSize = UNLIKELY(getAttribute(HasDynPropArr)) ? dynPropArray().size() : 0;
  size_t otherSize = 0;
  ArrayData* otherDynProps = nullptr;
  if (UNLIKELY(other.getAttribute(HasDynPropArr))) {
    otherDynProps = other.dynPropArray().get();
    otherSize = otherDynProps->size();
  }
  if (thisSize > otherSize) {
    return 1;
  } else if (thisSize < otherSize) {
    return -1;
  }

  
  check_recursion_error();

  int64_t result = 0;
  IteratePropToArrayOrderNoInc( this, [&](Slot slot, const Class::Prop& prop, tv_rval thisVal) {

      auto otherVal = other.propRvalAtOffset(slot);
      if ((UNLIKELY(thisVal.type() == KindOfUninit) || UNLIKELY(otherVal.type() == KindOfUninit)) && (prop.attrs & AttrLateInit)) {

        throw_late_init_prop(prop.cls, prop.name, false);
      }
      auto cmp = tvCompare(thisVal.tv(), otherVal.tv());
      if (cmp != 0) {
        result = cmp;
        return true;
      }
      return false;
    }, [&](TypedValue key, TypedValue thisVal) {
      auto const otherVal = otherDynProps->get(key);
      if (!otherVal.is_init()) {
        result = 1;
        return true;
      }
      auto cmp = tvCompare(thisVal, otherVal);
      if (cmp != 0) {
        result = cmp;
        return true;
      }
      return false;
    }
  );
  return result;
}



const StaticString s___sleep("__sleep"), s___toDebugDisplay("__toDebugDisplay"), s___wakeup("__wakeup"), s___debugInfo("__debugInfo");




void deepInitHelper(ObjectProps* props, const Class::PropInitVec* initVec, size_t nProps) {

  auto initIter = initVec->cbegin();
  props->init(nProps);
  props->foreach(nProps, [&](tv_lval lval){
    auto entry = *initIter++;
    tvCopy(entry.val.tv(), lval);
    if (entry.deepInit) {
      tvIncRefGen(*lval);
      collections::deepCopy(lval);
    }
  });
}

void ObjectData::setReifiedGenerics(Class* cls, ArrayData* reifiedTypes) {
  auto const arg = make_array_like_tv(reifiedTypes);
  auto const meth = cls->lookupMethod(s_86reifiedinit.get());
  assertx(meth != nullptr);
  g_context->invokeMethod(this, meth, InvokeArgs(&arg, 1));
}


ObjectData* ObjectData::newInstanceRawSmall(Class* cls, size_t size, size_t index) {
  assertx(size <= kMaxSmallSize);
  assertx(!cls->hasMemoSlots());
  assertx(cls->sizeIdx() == index);
  auto mem = tl_heap->mallocSmallIndexSize(index, size);
  auto const flags = IsBeingConstructed | SmallAllocSize;
  return new (NotNull{}, mem) ObjectData(cls, InitRaw{}, flags);
}

ObjectData* ObjectData::newInstanceRawBig(Class* cls, size_t size) {
  assertx(!cls->hasMemoSlots());
  auto mem = tl_heap->mallocBigSize(size);
  auto const flags = IsBeingConstructed | BigAllocSize;
  return new (NotNull{}, mem) ObjectData(cls, InitRaw{}, flags);
}


ObjectData* ObjectData::newInstanceRawMemoSmall(Class* cls, size_t size, size_t index, size_t objoff) {


  assertx(size <= kMaxSmallSize);
  assertx(cls->hasMemoSlots());
  assertx(!cls->getNativeDataInfo());
  assertx(objoff == ObjectData::objOffFromMemoNode(cls));
  assertx(cls->sizeIdx() == index);
  auto mem = tl_heap->mallocSmallIndexSize(index, size);
  new (NotNull{}, mem) MemoNode(objoff);
  mem = reinterpret_cast<char*>(mem) + objoff;
  auto const flags = IsBeingConstructed | SmallAllocSize;
  return new (NotNull{}, mem) ObjectData(cls, InitRaw{}, flags);
}

ObjectData* ObjectData::newInstanceRawMemoBig(Class* cls, size_t size, size_t objoff) {

  assertx(cls->hasMemoSlots());
  assertx(!cls->getNativeDataInfo());
  assertx(objoff == ObjectData::objOffFromMemoNode(cls));
  auto mem = tl_heap->mallocBigSize(size);
  new (NotNull{}, mem) MemoNode(objoff);
  mem = reinterpret_cast<char*>(mem) + objoff;
  auto const flags = IsBeingConstructed | BigAllocSize;
  return new (NotNull{}, mem) ObjectData(cls, InitRaw{}, flags);
}



ObjectData::~ObjectData() {
  if (UNLIKELY(slowDestroyCheck())) {
    
    
    
    assertx(!getAttribute(UsedMemoCache) || hasNativeData());
    if (getAttribute(HasDynPropArr)) freeDynPropArray(this);
    if (getAttribute(IsWeakRefed)) {
      WeakRefData::invalidateWeakRef((uintptr_t)this);
    }
  }
}

Object ObjectData::FromArray(ArrayData* properties) {
  assertx(properties->isPHPArrayType());
  Object retval{SystemLib::s_stdclassClass};
  retval->setAttribute(HasDynPropArr);
  g_context->dynPropTable.emplace(retval.get(), properties);
  return retval;
}

NEVER_INLINE void ObjectData::throwMutateConstProp(Slot prop) const {
  throw_cannot_modify_const_prop( getClassName().data(), m_cls->declProperties()[prop].name->data()

  );
}

template <bool forWrite, bool forRead, bool ignoreLateInit> ALWAYS_INLINE ObjectData::PropLookup ObjectData::getPropImpl( const Class* ctx, const StringData* key ) {




  auto const lookup = m_cls->getDeclPropSlot(ctx, key);
  auto const propSlot = lookup.slot;

  if (LIKELY(propSlot != kInvalidSlot)) {
    
    
    auto const propIndex = m_cls->propSlotToIndex(propSlot);
    auto prop = props()->at(propIndex);
    assertx(assertTypeHint(prop, propSlot));

    auto const& declProp = m_cls->declProperties()[propSlot];
    if (!ignoreLateInit && lookup.accessible) {
      if (UNLIKELY(type(prop) == KindOfUninit) && (declProp.attrs & AttrLateInit)) {
        throw_late_init_prop(declProp.cls, key, false);
      }
    }

    return {
     prop, &declProp, propSlot, lookup.accessible,    forWrite ? bool(declProp.attrs & AttrIsConst)







       : true };
  }

  
  
  if (UNLIKELY(getAttribute(HasDynPropArr))) {
    auto& arr = dynPropArray();
    if (arr->exists(key)) {
      if (forRead && RuntimeOption::EvalNoticeOnReadDynamicProp) {
        raiseReadDynamicProp(key);
      }
      
      
      
      auto const lval = arr.lval(StrNR(key), AccessFlags::Key);
      return { lval, nullptr, kInvalidSlot, true, !forWrite };
    }
  }

  return { nullptr, nullptr, kInvalidSlot, false, !forWrite };
}

tv_lval ObjectData::getPropLval(const Class* ctx, const StringData* key) {
  auto const lookup = getPropImpl<true, false, true>(ctx, key);
  if (UNLIKELY(lookup.isConst) && !isBeingConstructed()) {
    throwMutateConstProp(lookup.slot);
  }
  return lookup.val && lookup.accessible ? lookup.val : nullptr;
}

tv_rval ObjectData::getProp(const Class* ctx, const StringData* key) const {
  auto const lookup = const_cast<ObjectData*>(this)
    ->getPropImpl<false, true, false>(ctx, key);
  return lookup.val && lookup.accessible ? lookup.val : nullptr;
}

tv_rval ObjectData::getPropIgnoreLateInit(const Class* ctx, const StringData* key) const {
  auto const lookup = const_cast<ObjectData*>(this)
    ->getPropImpl<false, true, true>(ctx, key);
  return lookup.val && lookup.accessible ? lookup.val : nullptr;
}

tv_lval ObjectData::getPropIgnoreAccessibility(const StringData* key) {
  auto const lookup = getPropImpl<false, true, true>(nullptr, key);
  auto prop = lookup.val;
  if (!prop) return nullptr;
  if (lookup.prop && type(prop) == KindOfUninit && (lookup.prop->attrs & AttrLateInit)) {
    throw_late_init_prop(lookup.prop->cls, key, false);
  }
  return prop;
}



inline InvokeResult::InvokeResult(bool ok, Variant&& v) :
  val(*v.asTypedValue()) {
  tvWriteUninit(*v.asTypedValue());
  val.m_aux.u_ok = ok;
}

static InvokeResult guardedNativePropResult(Variant result) {
  if (!Native::isPropHandled(result)) {
    return {false, make_tv<KindOfUninit>()};
  }
  return InvokeResult{true, std::move(result)};
}

InvokeResult ObjectData::invokeNativeGetProp(const StringData* key) {
  return guardedNativePropResult( Native::getProp(Object{this}, StrNR(key))
  );
}

bool ObjectData::invokeNativeSetProp(const StringData* key, TypedValue val) {
  auto r = guardedNativePropResult( Native::setProp(Object{this}, StrNR(key), tvAsCVarRef(&val))
  );
  tvDecRefGen(r.val);
  return r.ok();
}

InvokeResult ObjectData::invokeNativeIssetProp(const StringData* key) {
  return guardedNativePropResult( Native::issetProp(Object{this}, StrNR(key))
  );
}

bool ObjectData::invokeNativeUnsetProp(const StringData* key) {
  auto r = guardedNativePropResult( Native::unsetProp(Object{this}, StrNR(key))
  );
  tvDecRefGen(r.val);
  return r.ok();
}



template<ObjectData::PropMode mode> ALWAYS_INLINE tv_lval ObjectData::propImpl(TypedValue* tvRef, const Class* ctx, const StringData* key) {


  auto constexpr write = (mode == PropMode::DimForWrite);
  auto constexpr read = (mode == PropMode::ReadNoWarn) || (mode == PropMode::ReadWarn);
  auto const lookup = getPropImpl<write, read, false>(ctx, key);
  auto const prop = lookup.val;

  if (prop) {
    if (lookup.accessible) {
      auto const checkConstProp = [&]() {
        if (mode == PropMode::DimForWrite) {
          if (UNLIKELY(lookup.isConst) && !isBeingConstructed()) {
            throwMutateConstProp(lookup.slot);
          }
        }
        return prop;
      };

      
      if (type(prop) != KindOfUninit) return checkConstProp();

      if (mode == PropMode::ReadWarn) raiseUndefProp(key);
      if (write) return checkConstProp();
      return const_cast<TypedValue*>(&immutable_null_base);
    }

    
    
    auto const propSlot = m_cls->lookupDeclProp(key);
    auto const attrs = m_cls->declProperties()[propSlot].attrs;
    auto const priv = (attrs & AttrPrivate) ? "private" : "protected";

    raise_error( "Cannot access %s property %s::$%s", priv, m_cls->preClass()->name()->data(), key->data()



    );
  }

  
  if (m_cls->rtAttribute(Class::HasNativePropHandler)) {
    if (auto r = invokeNativeGetProp(key)) {
      tvCopy(r.val, *tvRef);
      return tvRef;
    }
  }

  if (UNLIKELY(!*key->data())) {
    throw_invalid_property_name(StrNR(key));
  }

  if (mode == PropMode::ReadWarn) raiseUndefProp(key);
  if (write) return makeDynProp(key);
  return const_cast<TypedValue*>(&immutable_null_base);
}

tv_lval ObjectData::prop( TypedValue* tvRef, const Class* ctx, const StringData* key ) {



  return propImpl<PropMode::ReadNoWarn>(tvRef, ctx, key);
}

tv_lval ObjectData::propW( TypedValue* tvRef, const Class* ctx, const StringData* key ) {



  return propImpl<PropMode::ReadWarn>(tvRef, ctx, key);
}

tv_lval ObjectData::propU( TypedValue* tvRef, const Class* ctx, const StringData* key ) {



  return propImpl<PropMode::DimForWrite>(tvRef, ctx, key);
}

tv_lval ObjectData::propD( TypedValue* tvRef, const Class* ctx, const StringData* key ) {



  return propImpl<PropMode::DimForWrite>(tvRef, ctx, key);
}

bool ObjectData::propIsset(const Class* ctx, const StringData* key) {
  auto const lookup = getPropImpl<false, true, true>(ctx, key);
  if (lookup.val && lookup.accessible) {
    if (lookup.val.type() != KindOfUninit) {
      return lookup.val.type() != KindOfNull;
    }
    if (lookup.prop && (lookup.prop->attrs & AttrLateInit)) {
      return false;
    }
  }

  if (m_cls->rtAttribute(Class::HasNativePropHandler)) {
    if (auto r = invokeNativeIssetProp(key)) {
      tvCastToBooleanInPlace(&r.val);
      return r.val.m_data.num;
    }
  }

  return false;
}

void ObjectData::setProp(Class* ctx, const StringData* key, TypedValue val) {
  assertx(tvIsPlausible(val));
  assertx(val.m_type != KindOfUninit);

  auto const lookup = getPropImpl<true, false, true>(ctx, key);
  auto const prop = lookup.val;

  if (prop && lookup.accessible) {
    if (UNLIKELY(lookup.isConst) && !isBeingConstructed()) {
      throwMutateConstProp(lookup.slot);
    }
    
    
    Variant tmp = tvAsVariant(&val);
    verifyTypeHint(m_cls, lookup.prop, tmp.asTypedValue());
    tvMove(tmp.detach(), prop);
    return;
  }

  
  if (m_cls->rtAttribute(Class::HasNativePropHandler) && invokeNativeSetProp(key, val)) {
    return;
  }

  if (prop) raise_error("Cannot access protected property");

  if (UNLIKELY(!*key->data())) {
    throw_invalid_property_name(StrNR(key));
  }
  setDynProp(key, val);
}

tv_lval ObjectData::setOpProp(TypedValue& tvRef, Class* ctx, SetOpOp op, const StringData* key, TypedValue* val) {



  auto const lookup = getPropImpl<true, true, false>(ctx, key);
  auto prop = lookup.val;

  if (prop && lookup.accessible) {
    if (UNLIKELY(lookup.isConst) && !isBeingConstructed()) {
      throwMutateConstProp(lookup.slot);
    }

    auto const needsCheck = lookup.prop && [&] {
      auto const& tc = lookup.prop->typeConstraint;
      if (setOpNeedsTypeCheck(tc, op, prop)) {
        return true;
      }
      for (auto& ub : lookup.prop->ubs) {
        if (setOpNeedsTypeCheck(ub, op, prop)) return true;
      }
      return false;
    }();

    if (needsCheck) {
      
      TypedValue temp;
      tvDup(*prop, temp);
      SCOPE_FAIL { tvDecRefGen(&temp); };
      setopBody(&temp, op, val);
      verifyTypeHint(m_cls, lookup.prop, &temp);
      tvMove(temp, prop);
    } else {
      setopBody(prop, op, val);
    }
    return prop;
  }

  if (UNLIKELY(!*key->data())) throw_invalid_property_name(StrNR(key));

  
  if (m_cls->rtAttribute(Class::HasNativePropHandler)) {
    if (auto r = invokeNativeGetProp(key)) {
      tvCopy(r.val, tvRef);
      setopBody(&tvRef, op, val);
      if (invokeNativeSetProp(key, tvRef)) {
        return &tvRef;
      }
    }
    
  }

  if (prop) raise_error("Cannot access protected property");

  
  
  
  prop = makeDynProp(key);
  assertx(type(prop) == KindOfNull); 
  setopBody(prop, op, val);
  return prop;
}

TypedValue ObjectData::incDecProp(Class* ctx, IncDecOp op, const StringData* key) {
  auto const lookup = getPropImpl<true, true, false>(ctx, key);
  auto prop = lookup.val;

  if (prop && lookup.accessible) {
    if (UNLIKELY(lookup.isConst) && !isBeingConstructed()) {
      throwMutateConstProp(lookup.slot);
    }
    if (type(prop) == KindOfUninit) {
      tvWriteNull(prop);
    }

    
    auto const fast = [&]{
      if (RuntimeOption::EvalCheckPropTypeHints <= 0) return true;
      auto const isAnyCheckable = lookup.prop && [&] {
        if (lookup.prop->typeConstraint.isCheckable()) return true;
        for (auto const& ub : lookup.prop->ubs) {
          if (ub.isCheckable()) return true;
        }
        return false;
      }();
      if (!isAnyCheckable) return true;

      if (!isIntType(type(prop))) return false;
      return op == IncDecOp::PreInc || op == IncDecOp::PostInc || op == IncDecOp::PreDec || op == IncDecOp::PostDec;

    }();
    if (fast) return IncDecBody(op, tvAssertPlausible(prop));

    TypedValue temp;
    tvDup(tvAssertPlausible(*prop), temp);
    SCOPE_FAIL { tvDecRefGen(&temp); };
    auto result = IncDecBody(op, &temp);
    SCOPE_FAIL { tvDecRefGen(&result); };
    verifyTypeHint(m_cls, lookup.prop, &temp);
    tvMove(temp, tvAssertPlausible(prop));
    return result;
  }

  if (UNLIKELY(!*key->data())) throw_invalid_property_name(StrNR(key));

  
  if (m_cls->rtAttribute(Class::HasNativePropHandler)) {
    if (auto r = invokeNativeGetProp(key)) {
      SCOPE_EXIT { tvDecRefGen(r.val); };
      auto const dest = IncDecBody(op, tvAssertPlausible(&r.val));
      if (invokeNativeSetProp(key, tvAssertPlausible(r.val))) {
        return dest;
      }
    }
  }

  if (prop) raise_error("Cannot access protected property");

  
  
  
  prop = makeDynProp(key);
  assertx(type(prop) == KindOfNull); 
  return IncDecBody(op, prop);
}

void ObjectData::unsetProp(Class* ctx, const StringData* key) {
  auto const lookup = getPropImpl<true, false, true>(ctx, key);
  auto const prop = lookup.val;

  if (prop && lookup.accessible && (type(prop) != KindOfUninit || (lookup.prop && (lookup.prop->attrs & AttrLateInit)))) {

    if (lookup.slot != kInvalidSlot) {
      
      if (UNLIKELY(lookup.isConst) && !isBeingConstructed()) {
        throwMutateConstProp(lookup.slot);
      }
      unsetTypeHint(lookup.prop);
      tvSet(*uninit_variant.asTypedValue(), prop);
    } else {
      
      dynPropArray().remove(StrNR(key).asString(), true );
    }
    return;
  }

  
  if (m_cls->rtAttribute(Class::HasNativePropHandler) && invokeNativeUnsetProp(key)) {
    return;
  }

  if (prop && !lookup.accessible) {
    
    raise_error("Cannot unset inaccessible property");
  }

  if (UNLIKELY(!*key->data())) {
    throw_invalid_property_name(StrNR(key));
  }
}

void ObjectData::raiseObjToIntNotice(const char* clsName) {
  raise_notice("Object of class %s could not be converted to int", clsName);
}

void ObjectData::raiseObjToDoubleNotice(const char* clsName) {
  raise_notice("Object of class %s could not be converted to float", clsName);
}

void ObjectData::raiseAbstractClassError(Class* cls) {
  Attr attrs = cls->attrs();
  raise_error("Cannot instantiate %s %s", (attrs & AttrInterface) ? "interface" :
              (attrs & AttrTrait)     ? "trait" :
              (attrs & AttrEnum)      ? "enum" : "abstract class", cls->preClass()->name()->data());
}

void ObjectData::raiseUndefProp(const StringData* key) const {
  raise_notice("Undefined property: %s::$%s", m_cls->name()->data(), key->data());
}

void ObjectData::raiseCreateDynamicProp(const StringData* key) const {
  if (m_cls == SystemLib::s_stdclassClass || m_cls == SystemLib::s___PHP_Incomplete_ClassClass) {
    
    return;
  }
  if (key->isStatic()) {
    raise_notice("Created dynamic property with static name %s::%s", m_cls->name()->data(), key->data());
  } else {
    raise_notice("Created dynamic property with dynamic name %s::%s", m_cls->name()->data(), key->data());
  }
}

void ObjectData::raiseReadDynamicProp(const StringData* key) const {
  if (m_cls == SystemLib::s_stdclassClass || m_cls == SystemLib::s___PHP_Incomplete_ClassClass) {
    
    return;
  }
  if (key->isStatic()) {
    raise_notice("Read dynamic property with static name %s::%s", m_cls->name()->data(), key->data());
  } else {
    raise_notice("Read dynamic property with dynamic name %s::%s", m_cls->name()->data(), key->data());
  }
}

void ObjectData::raiseImplicitInvokeToString() const {
  raise_notice("Implicitly invoked %s::__toString", m_cls->name()->data());
}

Variant ObjectData::InvokeSimple(ObjectData* obj, const StaticString& name) {
  auto const meth = obj->methodNamed(name.get());
  return meth ? g_context->invokeMethodV(obj, meth, InvokeArgs{}, false)
    : uninit_null();
}

Variant ObjectData::invokeSleep() {
  return InvokeSimple(this, s___sleep);
}

Variant ObjectData::invokeToDebugDisplay() {
  return InvokeSimple(this, s___toDebugDisplay);
}

Variant ObjectData::invokeWakeup() {
  unlockObject();
  SCOPE_EXIT { lockObject(); };
  return InvokeSimple(this, s___wakeup);
}

Variant ObjectData::invokeDebugInfo() {
  return InvokeSimple(this, s___debugInfo);
}

String ObjectData::invokeToString() {
  if (RuntimeOption::EvalFatalOnConvertObjectToString) {
    raise_convert_object_to_string(classname_cstr());
  }

  const Func* method = m_cls->getToString();
  if (!method) {
    
    
    raise_recoverable_error( "Object of class %s could not be converted to string", classname_cstr()

    );
    
    
    return empty_string();
  }
  if (RuntimeOption::EvalNoticeOnImplicitInvokeToString) {
    raiseImplicitInvokeToString();
  }
  auto const tv = g_context->invokeMethod(this, method, InvokeArgs{}, false);
  if (!isStringType(tv.m_type)) {
    
    
    tvDecRefGen(tv);
    raise_recoverable_error( "Method %s::__toString() must return a string value", m_cls->preClass()->name()->data());

    
    
    return empty_string();
  }

  return String::attach(tv.m_data.pstr);
}

bool ObjectData::hasToString() {
  return (m_cls->getToString() != nullptr);
}

const char* ObjectData::classname_cstr() const {
  return getClassName().data();
}

} 
