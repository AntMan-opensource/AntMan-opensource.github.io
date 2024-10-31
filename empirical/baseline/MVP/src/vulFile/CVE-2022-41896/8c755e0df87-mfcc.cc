







namespace tensorflow {

const double kDefaultUpperFrequencyLimit = 4000;
const double kDefaultLowerFrequencyLimit = 20;
const double kFilterbankFloor = 1e-12;
const int kDefaultFilterbankChannelCount = 40;
const int kDefaultDCTCoefficientCount = 13;

Mfcc::Mfcc()
    : initialized_(false), lower_frequency_limit_(kDefaultLowerFrequencyLimit), upper_frequency_limit_(kDefaultUpperFrequencyLimit), filterbank_channel_count_(kDefaultFilterbankChannelCount), dct_coefficient_count_(kDefaultDCTCoefficientCount) {}




bool Mfcc::Initialize(int input_length, double input_sample_rate) {
  bool initialized = mel_filterbank_.Initialize( input_length, input_sample_rate, filterbank_channel_count_, lower_frequency_limit_, upper_frequency_limit_);

  initialized &= dct_.Initialize(filterbank_channel_count_, dct_coefficient_count_);
  initialized_ = initialized;
  return initialized;
}

void Mfcc::Compute(const std::vector<double>& spectrogram_frame, std::vector<double>* output) const {
  if (!initialized_) {
    LOG(ERROR) << "Mfcc not initialized.";
    return;
  }
  std::vector<double> working;
  mel_filterbank_.Compute(spectrogram_frame, &working);
  for (int i = 0; i < working.size(); ++i) {
    double val = working[i];
    if (val < kFilterbankFloor) {
      val = kFilterbankFloor;
    }
    working[i] = log(val);
  }
  dct_.Compute(working, output);
}

}  
