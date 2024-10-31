






























































namespace mlir {
namespace TFL {
namespace {





static Value CreateTFCastOpI32(OpBuilder *builder, Location loc, Value x, BoolAttr truncate) {
  auto x_type = x.getType().dyn_cast_or_null<ShapedType>();
  if (!x_type) llvm_unreachable("unsupported type");
  Type type = x_type.clone(builder->getI32Type());
  return builder->create<TF::CastOp>(loc, type, x, truncate);
}
}  






namespace {




class PrepareTFPass : public PrepareTFPassBase<PrepareTFPass> {
 public:
  MLIR_DEFINE_EXPLICIT_INTERNAL_INLINE_TYPE_ID(PrepareTFPass)

  PrepareTFPass() = default;
  PrepareTFPass(const PrepareTFPass &) {}
  explicit PrepareTFPass(bool unfold_batch_matmul, bool allow_bf16_and_f16_type_legalization, bool use_fake_quant_num_bits = false) {

    this->unfold_batch_matmul_ = unfold_batch_matmul;
    this->allow_bf16_and_f16_type_legalization_ = allow_bf16_and_f16_type_legalization;
    this->use_fake_quant_num_bits_ = use_fake_quant_num_bits;
  }

  void runOnOperation() override;
};


struct ConvertTFConvOpMatchState {
  IntegerAttr dilation_height_factor;
  IntegerAttr dilation_width_factor;
  StringAttr padding;
  IntegerAttr stride_height;
  IntegerAttr stride_width;
};















template <typename ConcreteType, typename TFConvOpType> class ConvertTFConvOp : public RewritePattern {
 public:
  ConvertTFConvOp(MLIRContext *context, bool allow_bf16_and_f16_type_legalization)
      : RewritePattern(TFConvOpType::getOperationName(), 1, context), intAttrOne(Builder(context).getI32IntegerAttr(1)), allow_bf16_and_f16_type_legalization_( allow_bf16_and_f16_type_legalization) {}



  LogicalResult matchAndRewrite(Operation *op, PatternRewriter &rewriter) const override {
    
    

    
    
    
    
    
    

    TFConvOpType tf_op = cast<TFConvOpType>(op);
    if (!TFTypeIsFloat32Tensor(tf_op.input()) && !(allow_bf16_and_f16_type_legalization_ && TFTypeIsBFloat16OrHalfTensor(tf_op.input())))

      return failure();

    if (!TFDataFormatIsNHWC(op)) return failure();

    IntegerAttr height, width;
    if (!TFIntListIs1XY1(op, "strides", &height, &width)) return failure();

    ConvertTFConvOpMatchState state;
    state.stride_height = height;
    state.stride_width = width;

    if (TFIntListIs1XY1(op, "dilations", &height, &width)) {
      state.dilation_height_factor = height;
      state.dilation_width_factor = width;
    } else {
      
      
      state.dilation_height_factor = intAttrOne;
      state.dilation_width_factor = intAttrOne;
    }

    TFPaddingIsSameOrValid(op, &state.padding);

    
    
    
    auto filter = tf_op.filter();
    auto filter_type = filter.getType().template dyn_cast<RankedTensorType>();
    if (!filter_type || filter_type.getRank() != 4 || !filter_type.hasStaticShape())
      return failure();

    Value input = tf_op.input();
    RankedTensorType input_type = input.getType().template dyn_cast<RankedTensorType>();
    
    
    if (!input_type || input_type.isDynamicDim(3)) {
      return failure();
    }
    
    
    if (input_type.getDimSize(3) % filter_type.getDimSize(2) != 0) {
      return failure();
    }

    
    
    
    
    
    

    

    
    auto elem_type = filter_type.getElementType();
    auto bias_dim = static_cast<const ConcreteType *>(this)->getBiasDim( filter_type.getShape());
    auto bias_type = RankedTensorType::get({bias_dim}, elem_type);
    auto bias_attr = rewriter.getZeroAttr(bias_type);
    auto bias = rewriter.create<TF::ConstOp>(op->getLoc(), bias_type, bias_attr);

    if (op->getAttrOfType<StringAttr>("padding").getValue() == "EXPLICIT") {
      
      ArrayRef<Attribute> padding_attr_array = op->getAttrOfType<ArrayAttr>("explicit_paddings").getValue();

      auto get_int = [](Attribute attr) {
        return attr.template cast<IntegerAttr>().getInt();
      };

      SmallVector<int32_t> padding_values(padding_attr_array.size());
      for (int i = 0; i < padding_attr_array.size(); i++) {
        padding_values[i] = static_cast<int32_t>(get_int(padding_attr_array[i]));
      }

      RankedTensorType padding_attr_type = RankedTensorType::get( {filter_type.getRank(), 2}, rewriter.getIntegerType(32));
      auto padding_attr = mlir::DenseIntElementsAttr::get(padding_attr_type, padding_values);

      auto padding_const = rewriter.create<TF::ConstOp>(op->getLoc(), padding_attr);

      
      auto pad_output_type = UnrankedTensorType::get(elem_type);
      input = rewriter.create<TF::PadOp>(op->getLoc(), pad_output_type, input, padding_const);

      
      state.padding = rewriter.getStringAttr("VALID");
    }
    auto conv_op = static_cast<const ConcreteType *>(this)->createTFLOp( &state, rewriter, op->getLoc(), tf_op.getType(), input, filter, bias);

    rewriter.replaceOp(op, conv_op.getResult());
    return success();
  }

  const IntegerAttr intAttrOne;

 private:
  bool allow_bf16_and_f16_type_legalization_;
};

class ConvertTFConv2D : public ConvertTFConvOp<ConvertTFConv2D, TF::Conv2DOp> {
 public:
  using BaseType = ConvertTFConvOp<ConvertTFConv2D, TF::Conv2DOp>;

  ConvertTFConv2D(MLIRContext *context, bool allow_bf16_type_legalization)
      : BaseType(context, allow_bf16_type_legalization) {}

  int64_t getBiasDim(ArrayRef<int64_t> filterShape) const {
    return filterShape.back();
  }

  TFL::Conv2DOp createTFLOp(ConvertTFConvOpMatchState *state, PatternRewriter &rewriter, Location loc, Type result_type, Value input, Value filter, Value bias) const {


    filter = legalizeFilter(rewriter, loc, filter);
    return rewriter.create<TFL::Conv2DOp>( loc, result_type, input, filter, bias, state->dilation_height_factor, state->dilation_width_factor, rewriter.getStringAttr("NONE"), state->padding, state->stride_height, state->stride_width);






  }

 private:
  
  
  
  
  Value legalizeFilter(PatternRewriter &rewriter, Location loc, Value filter) const {
    
    SmallVector<int, 4> perm = {3, 0, 1, 2};
    auto perm_type = RankedTensorType::get({static_cast<int>(perm.size())}, rewriter.getIntegerType(32));
    auto perm_attr = DenseElementsAttr::get(perm_type, llvm::makeArrayRef<int>(perm));
    auto perm_op = rewriter.create<TF::ConstOp>(loc, perm_type, perm_attr);

    
    auto filter_type = filter.getType().cast<RankedTensorType>();
    auto result_shape = llvm::to_vector<4>(llvm::map_range(perm, [filter_type](int64_t dim) {
          return filter_type.getDimSize(dim);
        }));
    auto elem_type = filter_type.getElementType();
    auto result_type = RankedTensorType::get(result_shape, elem_type);

    return rewriter.create<TF::TransposeOp>(loc, result_type, filter, perm_op);
  }
};

class ConvertTFDepthwiseConv2dNative : public ConvertTFConvOp<ConvertTFDepthwiseConv2dNative, TF::DepthwiseConv2dNativeOp> {

 public:
  using BaseType = ConvertTFConvOp<ConvertTFDepthwiseConv2dNative, TF::DepthwiseConv2dNativeOp>;

  ConvertTFDepthwiseConv2dNative(MLIRContext *context, bool allow_bf16_type_legalization)
      : BaseType(context, allow_bf16_type_legalization) {}

  int64_t getBiasDim(ArrayRef<int64_t> filterShape) const {
    return filterShape[2] * filterShape[3];
  }

  TFL::DepthwiseConv2DOp createTFLOp(ConvertTFConvOpMatchState *state, PatternRewriter &rewriter, Location loc, Type result_type, Value input, Value filter, Value bias) const {


    
    
    
    
    
    auto multiplier = filter.getType().cast<RankedTensorType>().getDimSize(3);

    filter = legalizeFilter(rewriter, loc, filter);
    return rewriter.create<TFL::DepthwiseConv2DOp>( loc, result_type, input, filter, bias, state->dilation_height_factor, state->dilation_width_factor, rewriter.getStringAttr("NONE"), state->padding, state->stride_height, state->stride_width, rewriter.getI32IntegerAttr(multiplier));







  }

 private:
  
  
  
  
  
  
  
  Value legalizeFilter(PatternRewriter &rewriter, Location loc, Value filter) const {
    auto filter_type = filter.getType().cast<RankedTensorType>();
    auto filterShape = filter_type.getShape();
    SmallVector<int64_t, 4> result_shape = {1, filterShape[0], filterShape[1], filterShape[2] * filterShape[3]};
    auto elem_type = filter_type.getElementType();
    auto result_type = RankedTensorType::get(result_shape, elem_type);
    
    auto shape_type = RankedTensorType::get({4}, rewriter.getIntegerType(32));
    SmallVector<Attribute, 4> result_shape_data(4);
    for (int i = 0; i < 4; ++i) {
      result_shape_data[i] = rewriter.getI32IntegerAttr(static_cast<int32_t>(result_shape[i]));
    }
    auto shape_attr = DenseElementsAttr::get(shape_type, result_shape_data);
    auto shape = rewriter.create<TF::ConstOp>(loc, shape_type, shape_attr);

    return rewriter.create<TF::ReshapeOp>(loc, result_type, filter, shape);
  }
};

















struct ConvertTFStridedSlice : public RewritePattern {
  explicit ConvertTFStridedSlice(MLIRContext *context)
      : RewritePattern(TF::StridedSliceOp::getOperationName(), 2, context) {}

  LogicalResult RewriteNewAxisMask(Operation *op, PatternRewriter &rewriter) const {
    TF::StridedSliceOp strided_slice_op = llvm::cast<TF::StridedSliceOp>(op);
    uint64_t new_axis_mask = strided_slice_op.new_axis_mask();

    if (strided_slice_op.ellipsis_mask() != 0) {
      
      
      op->emitError() << "encountered a logical error";
      return failure();
    }

    
    Value original_input = strided_slice_op.input();
    RankedTensorType original_input_type = original_input.getType().dyn_cast<RankedTensorType>();
    if (!original_input_type) {
      return failure();
    }

    const ArrayRef<int64_t> &original_input_shape = original_input_type.getShape();
    SmallVector<int64_t, 4> revised_shape;
    int index = 0;
    const int original_input_rank = original_input_shape.size();
    while (index < original_input_rank || new_axis_mask) {
      if (new_axis_mask & 1) {
        revised_shape.emplace_back(1);
      } else {
        revised_shape.emplace_back(original_input_shape[index++]);
      }
      new_axis_mask >>= 1;
    }

    if (failed(TF::VerifyShapeOfReshapeOp(revised_shape))) return failure();

    const int dim_size = revised_shape.size();
    Location loc = strided_slice_op.getLoc();
    auto shape_type = RankedTensorType::get({dim_size}, rewriter.getIntegerType(32));
    SmallVector<Attribute, 4> result_shape_data(dim_size);
    for (int i = 0; i < dim_size; ++i) {
      result_shape_data[i] = rewriter.getI32IntegerAttr(static_cast<int32_t>(revised_shape[i]));
    }

    auto shape_attr = DenseElementsAttr::get(shape_type, result_shape_data);
    auto shape = rewriter.create<arith::ConstantOp>(loc, shape_type, shape_attr);
    auto revised_output_type = RankedTensorType::get( revised_shape, original_input_type.getElementType());
    TF::ReshapeOp reshape = rewriter.create<TF::ReshapeOp>( loc, revised_output_type, original_input, shape);

    
    uint64_t revised_begin_mask = strided_slice_op.begin_mask();
    uint64_t revised_end_mask = strided_slice_op.end_mask();
    
    
    revised_begin_mask |= strided_slice_op.new_axis_mask();
    revised_end_mask |= strided_slice_op.new_axis_mask();

    
    uint64_t revised_shrink_axis_mask = strided_slice_op.shrink_axis_mask() & ~strided_slice_op.new_axis_mask();

    auto attribute_type = rewriter.getIntegerType(64);
    rewriter.replaceOpWithNewOp<TF::StridedSliceOp>( op, strided_slice_op.getType(), reshape, strided_slice_op.begin(), strided_slice_op.end(), strided_slice_op.strides(), rewriter.getIntegerAttr(attribute_type, revised_begin_mask), rewriter.getIntegerAttr(attribute_type, revised_end_mask), rewriter.getIntegerAttr(attribute_type, strided_slice_op.ellipsis_mask()), rewriter.getI64IntegerAttr(0), rewriter.getIntegerAttr(attribute_type, revised_shrink_axis_mask));







    return success();
  }

  LogicalResult RewriteEllipsisMask(Operation *op, PatternRewriter &rewriter) const {
    TF::StridedSliceOp strided_slice_op = llvm::cast<TF::StridedSliceOp>(op);

    uint64_t ellipsis_mask = strided_slice_op.ellipsis_mask();
    uint64_t shrink_axis_mask = strided_slice_op.shrink_axis_mask();
    uint64_t new_axis_mask = strided_slice_op.new_axis_mask();

    
    shrink_axis_mask &= ~ellipsis_mask;
    new_axis_mask &= ~ellipsis_mask;

    DenseIntElementsAttr begin_dense_elem_attr;
    Value begin = strided_slice_op.begin();
    auto begin_ranked_attr_type = begin.getType().dyn_cast<RankedTensorType>();
    if (!begin_ranked_attr_type || !matchPattern(begin, m_Constant(&begin_dense_elem_attr))) {
      return failure();
    }

    DenseIntElementsAttr end_dense_elem_attr;
    Value end = strided_slice_op.end();
    auto end_ranked_attr_type = end.getType().dyn_cast<RankedTensorType>();
    if (!end_ranked_attr_type || !matchPattern(end, m_Constant(&end_dense_elem_attr))) {
      return failure();
    }

    DenseIntElementsAttr stride_dense_elem_attr;
    Value stride = strided_slice_op.strides();
    auto stride_ranked_attr_type = stride.getType().dyn_cast<RankedTensorType>();
    if (!stride_ranked_attr_type || !matchPattern(stride, m_Constant(&stride_dense_elem_attr))) {
      return failure();
    }

    Value input = strided_slice_op.input();
    RankedTensorType input_type = input.getType().dyn_cast<RankedTensorType>();
    if (!input_type) {
      return failure();
    }
    const ArrayRef<int64_t> input_shape = input_type.getShape();

    const int input_size = input_shape.size();

    RankedTensorType begin_type = begin.getType().cast<RankedTensorType>();
    const ArrayRef<int64_t> begin_shape = begin_type.getShape();
    const int begin_dim = begin_shape.size();

    if (begin_dim != 1) return failure();

    
    
    const int ellipsis_filled_dim_size = input_size - begin_shape[0] + 1 + absl::popcount(new_axis_mask);

    int64_t begin_mask = strided_slice_op.begin_mask();
    int64_t end_mask = strided_slice_op.end_mask();
    int64_t revised_begin_mask = 0;
    int64_t revised_end_mask = 0;
    int64_t revised_shrink_axis_mask = 0;
    int64_t revised_new_axis_mask = 0;

    SmallVector<int32_t, 4> padded_begin;
    SmallVector<int32_t, 4> padded_end;
    SmallVector<int32_t, 4> padded_stride;

    
    int index = 0;
    int new_index = 0;
    while (((ellipsis_mask >> index) & 1) == 0) {
      padded_begin.push_back(begin_dense_elem_attr.getValues<int32_t>()[index]);
      padded_end.push_back(end_dense_elem_attr.getValues<int32_t>()[index]);
      padded_stride.push_back( stride_dense_elem_attr.getValues<int32_t>()[index]);
      if ((begin_mask >> index) & 1) revised_begin_mask |= (1 << new_index);
      if ((end_mask >> index) & 1) revised_end_mask |= (1 << new_index);
      if ((shrink_axis_mask >> index) & 1)
        revised_shrink_axis_mask |= (1 << new_index);

      if ((new_axis_mask >> index) & 1)
        revised_new_axis_mask |= (1 << new_index);

      ++index;
      ++new_index;
    }

    
    for (; new_index < index + ellipsis_filled_dim_size; ++new_index) {
      revised_begin_mask |= (1 << new_index);
      revised_end_mask |= (1 << new_index);

      
      padded_begin.push_back(0);
      padded_end.push_back(0);
      padded_stride.push_back(1);
    }

    
    ++index;

    
    for (; index < begin_shape[0];) {
      padded_begin.push_back(begin_dense_elem_attr.getValues<int32_t>()[index]);
      padded_end.push_back(end_dense_elem_attr.getValues<int32_t>()[index]);
      padded_stride.push_back( stride_dense_elem_attr.getValues<int32_t>()[index]);

      if ((begin_mask >> index) & 1) revised_begin_mask |= (1 << new_index);
      if ((end_mask >> index) & 1) revised_end_mask |= (1 << new_index);
      if ((shrink_axis_mask >> index) & 1)
        revised_shrink_axis_mask |= (1 << new_index);
      if ((new_axis_mask >> index) & 1)
        revised_new_axis_mask |= (1 << new_index);

      ++index;
      ++new_index;
    }

    auto attribute_type = rewriter.getIntegerType(64);

    int full_dim_count = padded_begin.size();
    auto type = RankedTensorType::get({full_dim_count}, rewriter.getIntegerType(32));

    auto begin_attr = DenseElementsAttr::get<int32_t>(type, padded_begin);
    auto begin_op = rewriter.create<arith::ConstantOp>(op->getLoc(), type, begin_attr);
    auto end_attr = DenseElementsAttr::get<int32_t>(type, padded_end);
    auto end_op = rewriter.create<arith::ConstantOp>(op->getLoc(), type, end_attr);
    auto stride_attr = DenseElementsAttr::get<int32_t>(type, padded_stride);
    auto stride_op = rewriter.create<arith::ConstantOp>(op->getLoc(), type, stride_attr);

    rewriter.replaceOpWithNewOp<TF::StridedSliceOp>( op, strided_slice_op.getType(), input, begin_op.getResult(), end_op.getResult(), stride_op.getResult(), rewriter.getIntegerAttr(attribute_type, revised_begin_mask), rewriter.getIntegerAttr(attribute_type, revised_end_mask), rewriter.getI64IntegerAttr(0), rewriter.getIntegerAttr(attribute_type, revised_new_axis_mask), rewriter.getIntegerAttr(attribute_type, revised_shrink_axis_mask));







    return success();
  }

  void PadStridedSliceAttributeArray(DenseIntElementsAttr dense_elem_attr, SmallVectorImpl<int32_t> &val, SmallVectorImpl<int32_t> &padded_val, ArrayRef<int32_t> padding_val, int *mask) const {



    for (const auto &idx : dense_elem_attr.getValues<APInt>()) {
      val.push_back(idx.getSExtValue());
      padded_val.push_back(idx.getSExtValue());
    }
    int attr_dim_count = val.size();
    int full_dim_count = padding_val.size();
    for (int i = attr_dim_count; i < full_dim_count; ++i) {
      padded_val.push_back(padding_val[i]);
      if (mask) *mask |= 1 << i;
    }
  }

  LogicalResult matchAndRewrite(Operation *op, PatternRewriter &rewriter) const override {
    TF::StridedSliceOp strided_slice_op = llvm::cast<TF::StridedSliceOp>(op);

    
    if (strided_slice_op.ellipsis_mask() != 0) {
      return RewriteEllipsisMask(strided_slice_op, rewriter);
    }

    
    if (strided_slice_op.new_axis_mask() != 0) {
      return RewriteNewAxisMask(strided_slice_op, rewriter);
    }

    auto ranked_input_type = strided_slice_op.input().getType().dyn_cast<RankedTensorType>();
    if (!ranked_input_type) {
      return failure();
    }

    auto begin_attr = strided_slice_op.begin();
    auto end_attr = strided_slice_op.end();
    auto strides_attr = strided_slice_op.strides();

    auto begin_attr_type = begin_attr.getType().dyn_cast<RankedTensorType>();
    auto end_attr_type = end_attr.getType().dyn_cast<RankedTensorType>();
    auto strides_attr_type = strides_attr.getType().dyn_cast<RankedTensorType>();

    DenseIntElementsAttr begin_elem_attr;
    DenseIntElementsAttr end_elem_attr;
    DenseIntElementsAttr strides_elem_attr;

    if (!begin_attr_type || !matchPattern(begin_attr, m_Constant(&begin_elem_attr))) {
      return failure();
    }
    if (!end_attr_type || !matchPattern(end_attr, m_Constant(&end_elem_attr))) {
      return failure();
    }
    if (!strides_attr_type || !matchPattern(strides_attr, m_Constant(&strides_elem_attr))) {
      return failure();
    }

    SmallVector<int32_t, 4> begin, end, strides;
    SmallVector<int32_t, 4> padded_begin, padded_end, padded_strides;

    int num_input_dims = ranked_input_type.getRank();
    SmallVector<int32_t, 4> padding_begin(num_input_dims, 0);
    auto input_shape = ranked_input_type.getShape();
    SmallVector<int32_t, 4> padding_end(input_shape.begin(), input_shape.end());
    SmallVector<int32_t, 4> padding_strides(num_input_dims, 1);

    int begin_mask = strided_slice_op.begin_mask();
    int end_mask = strided_slice_op.end_mask();

    PadStridedSliceAttributeArray(begin_elem_attr, begin, padded_begin, padding_begin, &begin_mask);
    PadStridedSliceAttributeArray(end_elem_attr, end, padded_end, padding_end, &end_mask);
    PadStridedSliceAttributeArray(strides_elem_attr, strides, padded_strides, padding_strides, nullptr);

    if (begin == padded_begin && end == padded_end && strides == padded_strides && begin_mask == strided_slice_op.begin_mask() && end_mask == strided_slice_op.end_mask()) {


      return failure();
    }

    auto begin_end_type = RankedTensorType::get({num_input_dims}, rewriter.getIntegerType(32));
    auto new_begin_attr = rewriter.create<arith::ConstantOp>( op->getLoc(), begin_end_type, DenseElementsAttr::get<int32_t>(begin_end_type, padded_begin));

    auto new_end_attr = rewriter.create<arith::ConstantOp>( op->getLoc(), begin_end_type, DenseElementsAttr::get<int32_t>(begin_end_type, padded_end));

    auto strides_type = RankedTensorType::get({static_cast<long>(padded_strides.size())}, rewriter.getIntegerType(32));

    auto new_strides_attr = rewriter.create<arith::ConstantOp>( op->getLoc(), strides_type, DenseElementsAttr::get<int32_t>(strides_type, padded_strides));


    auto attribute_type = rewriter.getIntegerType(64);
    rewriter.replaceOpWithNewOp<TF::StridedSliceOp>( op, strided_slice_op.output().getType(), strided_slice_op.input(), new_begin_attr, new_end_attr, new_strides_attr, rewriter.getIntegerAttr(attribute_type, begin_mask), rewriter.getIntegerAttr(attribute_type, end_mask), rewriter.getIntegerAttr(attribute_type, strided_slice_op.ellipsis_mask()), rewriter.getIntegerAttr(attribute_type, strided_slice_op.new_axis_mask()), rewriter.getIntegerAttr(attribute_type, strided_slice_op.shrink_axis_mask()));










    return success();
  }
};

struct ConvertTFBroadcastTo : public RewritePattern {
  explicit ConvertTFBroadcastTo(MLIRContext *context)
      : RewritePattern(TF::BroadcastToOp::getOperationName(), 1, context) {}

  LogicalResult matchAndRewrite(Operation *op, PatternRewriter &rewriter) const override {
    auto tf_broadcast_to_op = cast<TF::BroadcastToOp>(op);
    auto input_type = tf_broadcast_to_op.input().getType().cast<ShapedType>();
    auto output_type = tf_broadcast_to_op.output().getType().cast<ShapedType>();
    auto shape_type = tf_broadcast_to_op.shape().getType().cast<ShapedType>();
    Type element_type = input_type.getElementType();

    
    
    if (!((output_type.hasRank() && output_type.getRank() <= 4) || (shape_type.hasStaticShape() && shape_type.getRank() == 1 && shape_type.getDimSize(0) <= 4)))

      return failure();

    if (!(element_type.isa<BFloat16Type, Float32Type>() || element_type.isInteger(32) || element_type.isInteger(16)))
      return failure();

    auto status_or_const_op = CreateConstOpWithSingleValue(&rewriter, op->getLoc(), input_type, 1);
    if (!status_or_const_op.ok()) {
      return failure();
    }

    auto tf_fill_op = rewriter.create<TF::FillOp>( op->getLoc(), output_type, tf_broadcast_to_op.shape(), status_or_const_op.ValueOrDie());


    auto mul_op = rewriter.create<TF::MulOp>( op->getLoc(), output_type, tf_broadcast_to_op.input(), tf_fill_op);
    rewriter.replaceOp(op, mul_op.getResult());
    return success();
  }
};


















































































struct FusedBatchNormV3Pat : public ::mlir::RewritePattern {
  explicit FusedBatchNormV3Pat(::mlir::MLIRContext *context)
      : ::mlir::RewritePattern( "tf.FusedBatchNormV3", 1, context, {"tf.Add", "tf.Const", "tf.Mul", "tf.Rsqrt", "tf.Sub") {}


  ::mlir::LogicalResult matchAndRewrite( ::mlir::Operation *fused_batch_norm, ::mlir::PatternRewriter &rewriter) const override {

    
    Operation::operand_range mean(fused_batch_norm->getOperands());
    ::mlir::FloatAttr exponential_avg_factor;
    ::mlir::TF::FusedBatchNormV3Op root;
    Operation::operand_range offset(fused_batch_norm->getOperands());
    Operation::operand_range x(fused_batch_norm->getOperands());
    Operation::operand_range scale(fused_batch_norm->getOperands());
    Operation::operand_range variance(fused_batch_norm->getOperands());
    ::mlir::FloatAttr epsilon;
    ::mlir::BoolAttr is_training;

    
    auto fused_batch_norm_op = dyn_cast_or_null<::mlir::TF::FusedBatchNormV3Op>(fused_batch_norm);
    root = fused_batch_norm_op;
    x = fused_batch_norm_op.getODSOperands(0);
    scale = fused_batch_norm_op.getODSOperands(1);
    offset = fused_batch_norm_op.getODSOperands(2);
    mean = fused_batch_norm_op.getODSOperands(3);
    variance = fused_batch_norm_op.getODSOperands(4);

    ::mlir::Value mean_value = (*mean.begin());
    ::mlir::Value variance_value = (*variance.begin());

    if (!TFTypeIsFloat32Tensor(fused_batch_norm_op.x())) return failure();

    {
      epsilon = fused_batch_norm_op->getAttrOfType<::mlir::FloatAttr>("epsilon");
      if (!epsilon)
        epsilon = rewriter.getFloatAttr(rewriter.getF32Type(), 0.0001f);

      if (!(((epsilon.isa<::mlir::FloatAttr>())) && ((epsilon.cast<::mlir::FloatAttr>().getType().isF32())))) {
        return rewriter.notifyMatchFailure( fused_batch_norm_op, [&](::mlir::Diagnostic &diag) {
              diag << "op 'tf.FusedBatchNormV3' attribute 'epsilon' failed to " "satisfy constraint: 32-bit float attribute";
            });
      }
    }
    {
      exponential_avg_factor = fused_batch_norm_op->getAttrOfType<::mlir::FloatAttr>( "exponential_avg_factor");

      if (!exponential_avg_factor)
        exponential_avg_factor = rewriter.getFloatAttr(rewriter.getF32Type(), 1.0f);
    }
    if (!TFDataFormatIsNHWC(fused_batch_norm_op) && !TFDataFormatIsNDHWC(fused_batch_norm_op))
      return failure();

    if (!(((*root.getODSResults(1).begin()).use_empty()))) {
      return rewriter.notifyMatchFailure( fused_batch_norm_op, [&](::mlir::Diagnostic &diag) {
            diag << "entities '' failed to satisfy constraint: has no use";
          });
    }

    if (!(((*root.getODSResults(2).begin()).use_empty()))) {
      return rewriter.notifyMatchFailure( fused_batch_norm_op, [&](::mlir::Diagnostic &diag) {
            diag << "entities '' failed to satisfy constraint: has no use";
          });
    }

    if (!(((*root.getODSResults(3).begin()).use_empty()))) {
      return rewriter.notifyMatchFailure( fused_batch_norm_op, [&](::mlir::Diagnostic &diag) {
            diag << "entities '' failed to satisfy constraint: has no use";
          });
    }

    if (!(((*root.getODSResults(4).begin()).use_empty()))) {
      return rewriter.notifyMatchFailure( fused_batch_norm_op, [&](::mlir::Diagnostic &diag) {
            diag << "entities '' failed to satisfy constraint: has no use";
          });
    }

    if (!(((*root.getODSResults(5).begin()).use_empty()))) {
      return rewriter.notifyMatchFailure( fused_batch_norm_op, [&](::mlir::Diagnostic &diag) {
            diag << "entities '' failed to satisfy constraint: has no use";
          });
    }

    is_training = fused_batch_norm_op->getAttrOfType<::mlir::BoolAttr>("is_training");
    auto odsLoc = rewriter.getFusedLoc({fused_batch_norm->getLoc()});

    
    int64_t last_dim = -1;
    {
      auto is_last_dim_compatible = [](const Value &v, int64_t &last_dim) {
        auto v_type = v.getType().dyn_cast_or_null<RankedTensorType>();
        if (!v_type) return true;
        int64_t v_last_dim = v_type.getDimSize(v_type.getRank() - 1);
        if (v_last_dim == -1) return true;
        if (last_dim != -1 && v_last_dim != last_dim) return false;
        last_dim = v_last_dim;
        return true;
      };

      if (!is_last_dim_compatible(*x.begin(), last_dim) || !is_last_dim_compatible(*scale.begin(), last_dim) || !is_last_dim_compatible(*offset.begin(), last_dim)) {

        return rewriter.notifyMatchFailure( fused_batch_norm_op, [&](::mlir::Diagnostic &diag) {
              diag << "Shapes of scale and offset should be 1D and " "compatible with x";
            });
      }

      if (!is_training.getValue()) {
        if (!is_last_dim_compatible(mean_value, last_dim) || !is_last_dim_compatible(variance_value, last_dim)) {
          return rewriter.notifyMatchFailure( fused_batch_norm_op, [&](::mlir::Diagnostic &diag) {
                diag << "Shapes of mean and variance should be 1D and " "compatible with x";
              });
        }
      }

      
      auto x_type = (*x.begin()).getType();
      auto y_type = (*root.getODSResults(0).begin()).getType();
      if (!OpTrait::util::getBroadcastedType(x_type, y_type)) {
        return rewriter.notifyMatchFailure( fused_batch_norm_op, [&](::mlir::Diagnostic &diag) {
              diag << "Shapes of x and the first output should be compatible";
            });
      }
    }

    
    if (is_training.getValue()) {
      auto input_type = fused_batch_norm_op.x()
                            .getType()
                            .dyn_cast_or_null<RankedTensorType>();
      if (!input_type || input_type.getRank() != 4) {
        return rewriter.notifyMatchFailure( fused_batch_norm_op, [&](::mlir::Diagnostic &diag) {
              diag << "op 'tf.FusedBatchNormV3' that has 'is_training' equals " "True is only supported with input of rank 4";
            });
      }

      ::mlir::TF::ConstOp reduce_dim_op;
      {
        auto reduce_dim_type = ::mlir::RankedTensorType::get({3}, rewriter.getIntegerType(32));
        ::mlir::SmallVector<int32_t, 3> reduce_dim_values = {0, 1, 2};
        reduce_dim_op = rewriter.create<TF::ConstOp>( odsLoc, ::mlir::DenseIntElementsAttr::get(reduce_dim_type, reduce_dim_values));

      }

      auto new_mean_type = ::mlir::RankedTensorType::get({last_dim}, rewriter.getF32Type());
      ::mlir::TF::MeanOp mean_op_1;
      {
        ::mlir::Value x_value = (*x.begin());
        mean_op_1 = rewriter.create<TF::MeanOp>( odsLoc, new_mean_type, x_value, reduce_dim_op, rewriter.getBoolAttr(false));

      }

      ::mlir::TF::SquaredDifferenceOp square_diff_op;
      {
        ::mlir::Value tblgen_value_0 = (*x.begin());
        ::mlir::Value tblgen_value_1 = (*mean_op_1.getODSResults(0).begin());
        
        
        square_diff_op = rewriter.create<::mlir::TF::SquaredDifferenceOp>( odsLoc, tblgen_value_0, tblgen_value_1);
      }

      ::mlir::TF::MeanOp mean_op_2;
      {
        ::mlir::Value input_value = (*square_diff_op.getODSResults(0).begin());
        mean_op_2 = rewriter.create<TF::MeanOp>( odsLoc, new_mean_type, input_value, reduce_dim_op, rewriter.getBoolAttr(false));

      }

      mean_value = (*mean_op_1.getODSResults(0).begin());
      variance_value = (*mean_op_2.getODSResults(0).begin());
    }  

    ::llvm::SmallVector<::mlir::Value, 4> replace_values;
    ::mlir::TF::ConstOp epsilon_const_op;
    {
      epsilon_const_op = rewriter.create<::mlir::TF::ConstOp>(odsLoc, epsilon);

    }
    ::mlir::TF::AddOp add_op_1;
    {
      ::mlir::Value epsilon_value = (*epsilon_const_op.getODSResults(0).begin());
      
      add_op_1 = rewriter.create<::mlir::TF::AddOp>(odsLoc, variance_value, epsilon_value);

    }
    ::mlir::TF::RsqrtOp rsqrt_op;
    {
      ::mlir::SmallVector<::mlir::Value, 4> tblgen_values;
      ::mlir::SmallVector<::mlir::NamedAttribute, 4> tblgen_attrs;
      tblgen_values.push_back((*add_op_1.getODSResults(0).begin()));
      rsqrt_op = rewriter.create<::mlir::TF::RsqrtOp>(odsLoc, tblgen_values, tblgen_attrs);
    }
    ::mlir::TF::MulOp multiplier;
    {
      ::mlir::Value tblgen_value_0 = (*scale.begin());
      ::mlir::Value tblgen_value_1 = (*rsqrt_op.getODSResults(0).begin());
      multiplier = rewriter.create<::mlir::TF::MulOp>(odsLoc, tblgen_value_0, tblgen_value_1);

    }
    ::mlir::TF::MulOp mul_op_1;
    {
      ::mlir::Value tblgen_value_0 = (*x.begin());
      ::mlir::Value tblgen_value_1 = (*multiplier.getODSResults(0).begin());
      mul_op_1 = rewriter.create<::mlir::TF::MulOp>(odsLoc, tblgen_value_0, tblgen_value_1);

    }
    ::mlir::TF::MulOp mul_op_2;
    {
      ::mlir::Value multiplier_value = (*multiplier.getODSResults(0).begin());
      mul_op_2 = rewriter.create<::mlir::TF::MulOp>(odsLoc, mean_value, multiplier_value);

    }
    ::mlir::TF::SubOp sub_op;
    {
      ::mlir::Value tblgen_value_0 = (*offset.begin());
      ::mlir::Value tblgen_value_1 = (*mul_op_2.getODSResults(0).begin());
      sub_op = rewriter.create<::mlir::TF::SubOp>(odsLoc, tblgen_value_0, tblgen_value_1);

    }
    ::mlir::TF::AddOp add_op_2;
    {
      ::mlir::SmallVector<::mlir::Value, 4> tblgen_values;
      ::mlir::SmallVector<::mlir::NamedAttribute, 4> tblgen_attrs;
      tblgen_values.push_back((*mul_op_1.getODSResults(0).begin()));
      tblgen_values.push_back((*sub_op.getODSResults(0).begin()));
      ::mlir::SmallVector<::mlir::Type, 4> tblgen_types;
      for (auto v : fused_batch_norm_op.getODSResults(0)) {
        tblgen_types.push_back(v.getType());
      }
      add_op_2 = rewriter.create<::mlir::TF::AddOp>( odsLoc, tblgen_types, tblgen_values, tblgen_attrs);
    }
    for (auto v :
         ::llvm::SmallVector<::mlir::Value, 4>{add_op_2.getODSResults(0)}) {
      replace_values.push_back(v);
    }
    for (auto v : ::llvm::SmallVector<::mlir::Value, 4>{x}) {
      replace_values.push_back(v);
    }
    for (auto v : ::llvm::SmallVector<::mlir::Value, 4>{x}) {
      replace_values.push_back(v);
    }
    for (auto v : ::llvm::SmallVector<::mlir::Value, 4>{x}) {
      replace_values.push_back(v);
    }
    for (auto v : ::llvm::SmallVector<::mlir::Value, 4>{x}) {
      replace_values.push_back(v);
    }
    for (auto v : ::llvm::SmallVector<::mlir::Value, 4>{x}) {
      replace_values.push_back(v);
    }
    rewriter.replaceOp(fused_batch_norm, replace_values);
    return success();
  };
};





LogicalResult ValidateOp(Operation *op) {
  bool has_illegal_ops = false;
  op->walk([&](Operation *op) {
    if (isa<TF::VariableV2Op>(op)) {
      has_illegal_ops = true;
      op->emitOpError() << "is illegal in a TFLite pipeline";
    }
  });

  return failure(has_illegal_ops);
}



LogicalResult ConvertTf2XlaOps(func::FuncOp func, MLIRContext *context) {
  ConversionTarget target(*context);
  target.addLegalDialect<arith::ArithmeticDialect>();
  target.addLegalDialect<func::FuncDialect>();
  target.addLegalDialect<TF::TensorFlowDialect>();
  target.addLegalOp<ModuleOp>();
  target.addLegalOp<func::FuncOp>();
  target.addIllegalOp<TF::XlaConvV2Op>();
  target.addIllegalOp<TF::XlaGatherOp>();

  RewritePatternSet patterns(context);
  mhlo::PopulateLegalizeTfWithTf2XlaPatterns("XLA_CPU_JIT", patterns, context);
  mhlo::PopulateLegalizeTfPatterns(context, &patterns);
  TF::PopulateLegalizeHloToTfPatterns(&patterns, context);
  mhlo::GatherOp::getCanonicalizationPatterns(patterns, context);

  return applyPartialConversion(func, target, std::move(patterns));
}


















struct ConvertRfftToRfft2d : public RewritePattern {
  explicit ConvertRfftToRfft2d(MLIRContext *context)
      : RewritePattern(TF::RFFTOp::getOperationName(), 1, context) {}

  LogicalResult matchAndRewrite(Operation *op, PatternRewriter &rewriter) const override {
    auto rfft_op = dyn_cast<TF::RFFTOp>(op);

    auto input = rfft_op.input();
    auto input_type = input.getType().dyn_cast_or_null<RankedTensorType>();
    if (!input_type) return failure();
    auto fft_len = rfft_op.fft_length();
    auto fft_len_type = fft_len.getType().dyn_cast_or_null<ShapedType>();
    if (!fft_len_type) return failure();

    auto output_type = rfft_op.getResult().getType().dyn_cast_or_null<RankedTensorType>();
    if (!output_type) return failure();

    
    
    auto one_ele_type = mlir::RankedTensorType::get({1}, rewriter.getIntegerType(32));
    auto minus_two = CreateConstOpWithSingleValue(&rewriter, rfft_op.getLoc(), one_ele_type, -2);

    SmallVector<int64_t, 4> expanded_input_shape;
    SmallVector<int64_t, 4> expanded_output_shape;
    int expanded_rank = input_type.getRank() + 1;
    int r = 0;
    for (int i = 0; i < expanded_rank; ++i) {
      if (i == expanded_rank - 2) {
        expanded_input_shape.push_back(1);
        expanded_output_shape.push_back(1);
      } else {
        expanded_input_shape.push_back(input_type.getDimSize(r));
        expanded_output_shape.push_back(output_type.getDimSize(r));
        r++;
      }
    }

    auto expaned_input_type = mlir::RankedTensorType::get( expanded_input_shape, input_type.getElementType());
    TF::ExpandDimsOp expanded_input = rewriter.create<TF::ExpandDimsOp>( rfft_op.getLoc(), expaned_input_type, input, minus_two->getResult());

    
    auto one_attr = mlir::DenseIntElementsAttr::get(one_ele_type, {1});

    auto one = rewriter.create<TF::ConstOp>(rfft_op.getLoc(), one_attr);

    auto zero = CreateConstOpWithSingleValue(&rewriter, rfft_op.getLoc(), one_ele_type, 0);

    auto expanded_fft_len_type = mlir::RankedTensorType::get({2}, fft_len_type.getElementType());

    TF::ConcatV2Op expanded_fft_len = rewriter.create<TF::ConcatV2Op>( rfft_op.getLoc(), expanded_fft_len_type, SmallVector<Value, 2>({one.getResult(), fft_len}), zero->getResult());


    
    auto rfft2d_out_type = mlir::RankedTensorType::get( expanded_output_shape, output_type.getElementType());
    TF::RFFT2DOp rfft2d = rewriter.create<TF::RFFT2DOp>( rfft_op.getLoc(), rfft2d_out_type, expanded_input.getResult(), expanded_fft_len.getResult());


    
    auto squeeze_dim = rewriter.getI64ArrayAttr({-2});
    TF::SqueezeOp squeeze = rewriter.create<TF::SqueezeOp>( rfft_op.getLoc(), output_type, rfft2d.getResult(), squeeze_dim);

    rewriter.replaceOp(op, squeeze.getResult());

    return success();
  }
};




struct RemoveIdentity : public OpRewritePattern<TF::IdentityOp> {
  using OpRewritePattern<TF::IdentityOp>::OpRewritePattern;

  LogicalResult matchAndRewrite(TF::IdentityOp identity, PatternRewriter &rewriter) const override {
    
    if (identity.input().getType() == identity.getType()) {
      rewriter.replaceOp(identity, identity.input());
      return success();
    }
    
    
    
    
    
    for (Operation *user : identity->getUsers()) {
      if (user->getDialect()->getNamespace() != "tf") {
        return failure();
      }
    }

    rewriter.replaceOp(identity, identity.input());
    return success();
  }
};

void PrepareTFPass::runOnOperation() {
  MLIRContext *ctx = &getContext();
  RewritePatternSet patterns(ctx);
  RewritePatternSet phase_2_patterns(ctx);
  auto func = getOperation();

  
  
  
  
  if (failed(ValidateOp(func))) {
    func.emitError() << "tfl-prepare-tf pass failed.";
    signalPassFailure();
    return;
  }

  if (failed(ConvertTf2XlaOps(func, ctx))) {
    signalPassFailure();
    return;
  }

  
  
  
  patterns.add<ConvertTFDilatedConvOp<TF::Conv2DOp>, FusedBatchNormV3Pat, ConvertTFDilatedConvOp<TF::DepthwiseConv2dNativeOp>>(ctx);

  patterns.add<RemoveIdentity>(ctx);
  TFL::populateWithGenerated(patterns);
  
  
  
  
  
  (void)applyPatternsAndFoldGreedily(func, std::move(patterns));

  
  
  
  
  
  
  if (failed(ConvertFakeQuantOps(func, ctx, use_fake_quant_num_bits_))) {
    signalPassFailure();
    return;
  }

  
  
  TFL::populateWithGenerated(phase_2_patterns);
  if (unfold_batch_matmul_) {
    TF::PopulateUnrollTfBatchMatMul(ctx, phase_2_patterns);
  }
  phase_2_patterns .add<TF::ConvertTFEinsumOp, ConvertTFBroadcastTo, ConvertTFStridedSlice, ConvertRfftToRfft2d, RemoveIdentity>(ctx);

  phase_2_patterns.add<ConvertTFConv2D, ConvertTFDepthwiseConv2dNative>( ctx, allow_bf16_and_f16_type_legalization_);

  (void)applyPatternsAndFoldGreedily(func, std::move(phase_2_patterns));
}

}  


std::unique_ptr<OperationPass<func::FuncOp>> CreatePrepareTFPass( bool unfold_batch_matmul, bool allow_bf16_and_f16_type_legalization, bool use_fake_quant_num_bits) {

  return std::make_unique<PrepareTFPass>(unfold_batch_matmul, allow_bf16_and_f16_type_legalization, use_fake_quant_num_bits);

}


std::unique_ptr<OperationPass<func::FuncOp>> CreatePrepareTFPass() {
  return std::make_unique<PrepareTFPass>();
}

}  
}  
