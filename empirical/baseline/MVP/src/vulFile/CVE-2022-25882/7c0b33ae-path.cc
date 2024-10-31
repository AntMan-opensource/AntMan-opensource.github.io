






namespace ONNX_NAMESPACE {

std::string path_join(const std::string& origin, const std::string& append) {
  if (origin.find_last_of(k_preferred_path_separator) != origin.length() - k_preferred_path_separator.length()) {
    return origin + k_preferred_path_separator + append;
  }
  return origin + append;
}

} 
