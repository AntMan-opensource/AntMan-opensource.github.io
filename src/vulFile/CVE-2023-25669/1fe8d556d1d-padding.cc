









namespace xla {

Status ValidatePaddingValues(absl::Span<const int64_t> input_dimensions, absl::Span<const int64_t> window_dimensions, absl::Span<const int64_t> window_strides) {

  bool ok = input_dimensions.size() == window_dimensions.size() && input_dimensions.size() == window_strides.size();
  if (!ok) {
    return InvalidArgument( "Want input dimensions size %u = window dimensions size %u = window " "strides size %u", input_dimensions.size(), window_dimensions.size(), window_strides.size());



  }
  return OkStatus();
}

std::vector<std::pair<int64_t, int64_t>> MakePadding( absl::Span<const int64_t> input_dimensions, absl::Span<const int64_t> window_dimensions, absl::Span<const int64_t> window_strides, Padding padding) {


  TF_CHECK_OK(ValidatePaddingValues(input_dimensions, window_dimensions, window_strides));
  std::vector<std::pair<int64_t, int64_t>> low_high_padding;
  switch (padding) {
    case Padding::kValid:
      low_high_padding.resize(window_dimensions.size(), {0, 0});
      return low_high_padding;

    case Padding::kSame:
      for (size_t i = 0; i < input_dimensions.size(); ++i) {
        int64_t input_dimension = input_dimensions[i];
        int64_t window_dimension = window_dimensions[i];
        int64_t window_stride = window_strides[i];
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        int64_t output_dimension = tsl::MathUtil::CeilOfRatio(input_dimension, window_stride);
        int64_t padding_size = std::max<int64_t>((output_dimension - 1) * window_stride + window_dimension - input_dimension, 0);


        low_high_padding.emplace_back( tsl::MathUtil::FloorOfRatio(padding_size, int64_t{2}), tsl::MathUtil::CeilOfRatio(padding_size, int64_t{2}));

      }
      break;
  }

  return low_high_padding;
}

}  
