














namespace hermes {
namespace bigint {



static constexpr BigIntDigitType BigIntMaxSizeInBits = BigIntMaxSizeInDigits * BigIntDigitSizeInBits;

llvh::ArrayRef<uint8_t> dropExtraSignBits(llvh::ArrayRef<uint8_t> src) {
  if (src.empty()) {
    
    return src;
  }

  const uint8_t drop = getSignExtValue<uint8_t>(src.back());

  
  
  
  
  
  
  

  auto previousSrc = src;
  while (!src.empty() && src.back() == drop) {
    previousSrc = src;
    src = src.drop_back();
  }

  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  const uint8_t lastChar = src.empty() ? 0u : src.back();

  return getSignExtValue<uint8_t>(lastChar) == drop ? src : previousSrc;
}

namespace {

void ensureCanonicalResult(MutableBigIntRef &dst) {
  auto ptr = reinterpret_cast<uint8_t *>(dst.digits);
  const uint32_t sizeInBytes = dst.numDigits * BigIntDigitSizeInBytes;

  llvh::ArrayRef<uint8_t> compactView = dropExtraSignBits(llvh::makeArrayRef(ptr, sizeInBytes));
  dst.numDigits = numDigitsForSizeInBytes(compactView.size());
}

static OperationStatus initWithDigits( MutableBigIntRef dst, ImmutableBigIntRef src) {

  auto ptr = reinterpret_cast<const uint8_t *>(src.digits);
  auto size = src.numDigits * BigIntDigitSizeInBytes;
  return initWithBytes(dst, llvh::makeArrayRef(ptr, size));
}
} 





static_assert( llvh::support::endian::system_endianness() == llvh::support::little, "BigIntSupport expects little-endian host");


OperationStatus initWithBytes( MutableBigIntRef dst, llvh::ArrayRef<uint8_t> data) {

  const uint32_t dstSizeInBytes = dst.numDigits * BigIntDigitSizeInBytes;

  assert(dst.digits != nullptr && "buffer can't be nullptr");

  if (dstSizeInBytes < data.size()) {
    
    dst.numDigits = 0;
    return OperationStatus::DEST_TOO_SMALL;
  }

  const size_t dataSizeInBytes = data.size();

  if (dataSizeInBytes == 0) {
    
    dst.numDigits = 0;
    return OperationStatus::RETURNED;
  }

  
  auto *ptr = reinterpret_cast<uint8_t *>(dst.digits);

  
  
  memcpy(ptr, data.data(), dataSizeInBytes);

  
  
  
  const uint32_t numBytesToSet = dstSizeInBytes - dataSizeInBytes;
  const uint8_t signExtValue = getSignExtValue<uint8_t>(ptr[dataSizeInBytes - 1]);

  memset(ptr + dataSizeInBytes, signExtValue, numBytesToSet);

  ensureCanonicalResult(dst);
  return OperationStatus::RETURNED;
}

bool isNegative(ImmutableBigIntRef src) {
  return src.numDigits > 0 && static_cast<SignedBigIntDigitType>(src.digits[src.numDigits - 1]) < 0;
}

uint32_t fromDoubleResultSize(double src) {
  uint64_t srcI = llvh::bit_cast<uint64_t>(src);
  int64_t exp = ((srcI >> 52) & 0x7ff) - 1023;

  
  
  if (exp < 0)
    return 0;

  
  
  return numDigitsForSizeInBits(exp + 2);
}

OperationStatus fromDouble(MutableBigIntRef dst, double src) {
  assert( dst.numDigits >= fromDoubleResultSize(src) && "not enough digits provided for double conversion");

  
  
  const uint32_t MaxBitsToRepresentDouble = llvh::alignTo(1024 + 1, BigIntDigitSizeInBits);
  llvh::APInt tmp = llvh::APIntOps::RoundDoubleToAPInt(src, MaxBitsToRepresentDouble);

  auto *ptr = reinterpret_cast<const uint8_t *>(tmp.getRawData());
  auto size = tmp.getNumWords() * BigIntDigitSizeInBytes;
  auto bytesRef = llvh::makeArrayRef<uint8_t>(ptr, size);
  return initWithBytes(dst, dropExtraSignBits(bytesRef));
}

double toDouble(ImmutableBigIntRef src) {
  if (src.numDigits == 0) {
    return 0.0;
  }

  const uint32_t numBits = src.numDigits * BigIntDigitSizeInBits;
  llvh::APInt tmp(numBits, llvh::makeArrayRef(src.digits, src.numDigits));
  constexpr bool kSigned = true;
  return tmp.roundToDouble(kSigned);
}

namespace {


static inline bool isWhiteSpaceChar(char16_t c) {
  return c == u'\u0009' || c == u'\u000B' || c == u'\u000C' || c == u'\u0020' || c == u'\u00A0' || c == u'\uFEFF' || c == u'\u1680' || (c >= u'\u2000' && c <= u'\u200A') || c == u'\u202F' || c == u'\u205F' || c == u'\u3000';


}

template <typename ConcreteParser> struct ConcreteParserTraits;




template <typename ConcreteParser> class BigIntLiteralParsingToolBox {
  BigIntLiteralParsingToolBox(const BigIntLiteralParsingToolBox &) = delete;
  BigIntLiteralParsingToolBox &operator=(const BigIntLiteralParsingToolBox &) = delete;
  BigIntLiteralParsingToolBox(BigIntLiteralParsingToolBox &&) = delete;
  BigIntLiteralParsingToolBox &operator=(BigIntLiteralParsingToolBox &&) = delete;

 protected:
  using StringRefT = typename ConcreteParserTraits<ConcreteParser>::StringRefT;

  
  using CharT = std::remove_cv_t<std::remove_reference_t<decltype( *typename StringRefT::const_iterator{})>>;

  BigIntLiteralParsingToolBox( StringRefT str, uint8_t &radix, std::string &bigintDigits, ParsedSign &sign, std::string *outError)




      : it_(str.begin()),  begin_(str.begin()),  end_(str.end()), radix_(radix), bigintDigits_(bigintDigits), sign_(sign), outError_(outError) {







    bigintDigits_.clear();
    bigintDigits_.reserve(end_ - it_);

    sign_ = ParsedSign::None;
  }

  bool nonDecimalIntegerLiteral() {
    return binaryIntegerLiteral() || octalIntegerLiteral() || hexIntegerLiteral();
  }

  bool binaryIntegerLiteral() {


    if (lookaheadAndEatIfAnyOf<BIGINT_BINARY_PREFIX>()) {
      radix_ = 2;
      dispatchBuildBigIntWithDigitsToConcrete<BIGINT_BINARY_DIGITS>();
      return bigintDigits_.size() > 0;
    }

    return false;


  }

  bool octalIntegerLiteral() {


    if (lookaheadAndEatIfAnyOf<BIGINT_OCTAL_PREFIX>()) {
      radix_ = 8;
      dispatchBuildBigIntWithDigitsToConcrete<BIGINT_OCTAL_DIGITS>();
      return bigintDigits_.size() > 0;
    }

    return false;


  }

  bool hexIntegerLiteral() {




    if (lookaheadAndEatIfAnyOf<BIGINT_HEX_PREFIX>()) {
      radix_ = 16;
      dispatchBuildBigIntWithDigitsToConcrete<BIGINT_HEX_DIGITS>();
      return bigintDigits_.size() > 0;
    }

    return false;


  }

  bool nonZeroDecimalLiteral() {


    if (nextIsAnyOf<BIGINT_NONZERO_DEC_DIGITS>()) {
      radix_ = 10;
      dispatchBuildBigIntWithDigitsToConcrete<BIGINT_DEC_DIGITS>();
      return bigintDigits_.size() > 0;
    }
    return false;


  }

  bool decimalDigits() {
    
    auto ch0 = peek();
    while (ch0 && *ch0 == '0') {
      auto chNext = peek(1);
      if (!chNext) {
        break;
      }
      eat();
      ch0 = chNext;
    }


    if (nextIsAnyOf<BIGINT_DEC_DIGITS>()) {
      radix_ = 10;
      dispatchBuildBigIntWithDigitsToConcrete<BIGINT_DEC_DIGITS>();
      return bigintDigits_.size() > 0;
    }
    return false;

  }

  
  
  template <char... digits> void dispatchBuildBigIntWithDigitsToConcrete() {
    static_cast<ConcreteParser *>(this)
        ->template buildBigIntWithDigits<digits...>();
  }

  bool fail(const char *err) {
    if (outError_) {
      *outError_ = err;
    }
    return false;
  }

  bool checkEnd(const char *err) {
    auto ch = peek();
    
    
    return (ch && *ch != 0) ? fail(err) : true;
  }

  template <char c> static bool anyOf(char rhs) {
    return c == rhs;
  }

  template <CharT c, CharT d, CharT... rest> static bool anyOf(CharT rhs) {
    return (c == rhs) || anyOf<d, rest...>(rhs);
  }

  template <CharT... chars> OptValue<CharT> lookaheadAndEatIfAnyOf() {
    OptValue<CharT> ret;

    if (auto ch = nextIsAnyOf<chars...>()) {
      eat();
      ret = ch;
    }

    return ret;
  }

  template <CharT... chars> OptValue<CharT> nextIsAnyOf() {
    OptValue<CharT> ret;

    if (auto ch = peek()) {
      if (anyOf<chars...>(*ch)) {
        ret = ch;
      }
    }

    return ret;
  }

  
  using ParserState = typename StringRefT::const_iterator;

  
  
  
  ParserState getCurrentParserState() const {
    return it_;
  }

  
  void restoreParserState(const ParserState &state) {
    assert( begin_ <= state && "invalid parser state - pointing before input start");

    assert(state <= end_ && "invalid parser state - pointing past input end");
    it_ = state;
  }

  
  
  OptValue<CharT> eat() {
    OptValue<CharT> c = peek();
    if (c) {
      it_ += 1;
    }
    return c;
  }

  
  
  
  
  OptValue<CharT> peek(std::ptrdiff_t which = 0) const {
    OptValue<CharT> ret;
    if (it_ + which < end_) {
      ret = *(it_ + which);
    }
    return ret;
  }

  typename StringRefT::const_iterator it_;

  typename StringRefT::const_iterator begin_;

  typename StringRefT::const_iterator end_;
  uint8_t &radix_;
  std::string &bigintDigits_;
  ParsedSign &sign_;
  std::string *outError_;
};

template <typename StringRef> class StringIntegerLiteralParser;

template <typename T> struct ConcreteParserTraits<StringIntegerLiteralParser<T>> {
  using StringRefT = T;
};




template <typename StringRefT> class StringIntegerLiteralParser : public BigIntLiteralParsingToolBox< StringIntegerLiteralParser<StringRefT>> {

 public:
  using CharT = typename BigIntLiteralParsingToolBox< StringIntegerLiteralParser<StringRefT>>::CharT;

  StringIntegerLiteralParser( StringRefT str, uint8_t &radix, std::string &bigintDigits, ParsedSign &sign, std::string *outError)




      : BigIntLiteralParsingToolBox<StringIntegerLiteralParser<StringRefT>>( str, radix, bigintDigits, sign, outError) {




    if (this->it_ < this->end_ && *(this->end_ - 1) == 0) {
      --this->end_;
    }

    
    
    while (this->it_ < this->end_ && isWhiteSpaceChar(*this->it_)) {
      ++this->it_;
    }

    while (this->it_ < this->end_ && isWhiteSpaceChar(*(this->end_ - 1))) {
      --this->end_;
    }
  }

  
  
  
  bool goal() && {
    auto ch = this->peek();
    if (!ch) {
      this->radix_ = 10;
      this->bigintDigits_ = "0";
      return true;
    } else {
      if (*ch == '0') {
        
        
        auto atZero = this->getCurrentParserState();

        
        this->eat();

        
        if (this->nonDecimalIntegerLiteral()) {
          return this->checkEnd("trailing data in non-decimal literal");
        }

        
        
        this->restoreParserState(atZero);
      }

      if (auto signCh = this->template lookaheadAndEatIfAnyOf<'+', '-'>()) {
        this->sign_ = *ch == '+' ? ParsedSign::Plus : ParsedSign::Minus;
      }

      
      if (this->decimalDigits()) {
        return this->checkEnd("trailing data in decimal literal");
      }
    }

    return this->fail("invalid bigint literal");
  }

 public:
  template <CharT... digits> void buildBigIntWithDigits() {
    OptValue<CharT> ch = this->template lookaheadAndEatIfAnyOf<digits...>();
    while (ch.hasValue()) {
      this->bigintDigits_.push_back(*ch);
      ch = this->template lookaheadAndEatIfAnyOf<digits...>();
    }
  }
};

template <> struct ConcreteParserTraits<class NumericValueParser> {
  using StringRefT = llvh::StringRef;
};


class NumericValueParser : public BigIntLiteralParsingToolBox<NumericValueParser> {
 public:
  NumericValueParser( llvh::StringRef str, uint8_t &radix, std::string &bigintDigits, ParsedSign &sign, std::string *outError)




      : BigIntLiteralParsingToolBox(str, radix, bigintDigits, sign, outError) {}

  
  
  bool goal() && {
    if (auto ch = peek()) {
      if (*ch == '0') {
        
        eat();

        
        
        

        
        if (bigIntLiteralSuffix()) {
          radix_ = 10;
          bigintDigits_ = "0";
          return checkEnd("trailing data in 0n literal");
        }

        
        if (nonDecimalIntegerLiteral()) {
          if (bigIntLiteralSuffix()) {
            return checkEnd("trailing data in non-decimal literal");
          }

          return fail("no n suffix in non-decimal");
        }
      } else {
        
        if (nonZeroDecimalLiteral()) {
          if (bigIntLiteralSuffix()) {
            return checkEnd("trailing data in decimal literal");
          }

          return fail("no n suffix in decimal");
        }
      }
    }

    return fail("invalid bigint literal");
  }

  template <char... digits> void buildBigIntWithDigits() {
    OptValue<char> ch = lookaheadAndEatIfAnyOf<digits...>();
    while (ch.hasValue()) {
      bigintDigits_.push_back(*ch);
      auto atSep = getCurrentParserState();
      bool isSep = numericLiteralSeparator();
      ch = lookaheadAndEatIfAnyOf<digits...>();
      if (isSep && !ch) {
        restoreParserState(atSep);
      }
    }
  }

 private:
  bool numericLiteralSeparator() {
    return lookaheadAndEatIfAnyOf<'_'>().hasValue();
  }

  bool bigIntLiteralSuffix() {
    return lookaheadAndEatIfAnyOf<'n'>().hasValue();
  }
};




template <typename StringRefT> static unsigned numBitsForBigintDigits(StringRefT str, uint8_t radix) {
  assert( (radix == 2 || radix == 4 || radix == 8 || radix == 10 || radix == 16) && "unpected bigint radix");


  
  
  
  uint8_t maxBitsPerChar = radix == 10 ? 4 : llvh::findFirstSet(radix);

  
  
  return numDigitsForSizeInBits(maxBitsPerChar * str.size() + 1) * BigIntDigitSizeInBits;
}

template <typename ParserT, typename StringRefT> static std::optional<std::string> getDigitsWith( StringRefT src, uint8_t &radix, ParsedSign &sign, std::string *outError) {




  std::string bigintDigits;
  std::optional<std::string> ret;
  if (ParserT{src, radix, bigintDigits, sign, outError}.goal()) {
    ret = std::move(bigintDigits);
  }
  return ret;
}
} 

std::optional<std::string> getStringIntegerLiteralDigitsAndSign( llvh::ArrayRef<char> src, uint8_t &radix, ParsedSign &sign, std::string *outError) {



  return getDigitsWith<StringIntegerLiteralParser<llvh::ArrayRef<char>>>( src, radix, sign, outError);
}

std::optional<std::string> getStringIntegerLiteralDigitsAndSign( llvh::ArrayRef<char16_t> src, uint8_t &radix, ParsedSign &sign, std::string *outError) {



  return getDigitsWith<StringIntegerLiteralParser<llvh::ArrayRef<char16_t>>>( src, radix, sign, outError);
}

std::optional<std::string> getNumericValueDigits( llvh::StringRef src, uint8_t &radix, std::string *outError) {


  ParsedSign sign;
  return getDigitsWith<NumericValueParser>(src, radix, sign, outError);
}

namespace {
template <typename ParserT, typename StringRefT> static std::optional<std::vector<uint8_t>> parsedBigIntFrom( StringRefT input, std::string *outError) {


  uint8_t radix;
  ParsedSign sign;
  std::optional<std::string> bigintDigits = getDigitsWith<ParserT>(input, radix, sign, outError);

  std::optional<std::vector<uint8_t>> result;
  if (bigintDigits) {
    llvh::APInt i( numBitsForBigintDigits(*bigintDigits, radix), *bigintDigits, radix);

    assert( i.getBitWidth() % sizeof(llvh::APInt::WordType) == 0 && "Must always allocate full words");


    auto *ptr = reinterpret_cast<const uint8_t *>(i.getRawData());
    size_t size = i.getNumWords() * sizeof(llvh::APInt::WordType);

    if (sign == ParsedSign::Minus) {
      i.negate();
    }

    result = std::vector<uint8_t>(ptr, ptr + size);
  }

  return result;
}
} 

std::optional<ParsedBigInt> ParsedBigInt::parsedBigIntFromStringIntegerLiteral( llvh::ArrayRef<char> input, std::string *outError) {

  std::optional<ParsedBigInt> ret;
  if (auto maybeBytes = parsedBigIntFrom<StringIntegerLiteralParser<llvh::ArrayRef<char>>>( input, outError)) {

    ret = ParsedBigInt(*maybeBytes);
  }

  return ret;
}

std::optional<ParsedBigInt> ParsedBigInt::parsedBigIntFromStringIntegerLiteral( llvh::ArrayRef<char16_t> input, std::string *outError) {

  std::optional<ParsedBigInt> ret;
  if (auto maybeBytes = parsedBigIntFrom< StringIntegerLiteralParser<llvh::ArrayRef<char16_t>>>( input, outError)) {

    ret = ParsedBigInt(*maybeBytes);
  }

  return ret;
}

std::optional<ParsedBigInt> ParsedBigInt::parsedBigIntFromNumericValue( llvh::StringRef input, std::string *outError) {

  std::optional<ParsedBigInt> ret;
  if (auto maybeBytes = parsedBigIntFrom<NumericValueParser>(input, outError)) {
    ret = ParsedBigInt(std::move(*maybeBytes));
  }

  return ret;
}

std::string toString(ImmutableBigIntRef src, uint8_t radix) {
  assert(radix >= 2 && radix <= 36);

  if (compare(src, 0) == 0) {
    return "0";
  }

  const unsigned numBits = src.numDigits * BigIntDigitSizeInBytes * 8;
  const bool sign = isNegative(src);
  llvh::APInt tmp(numBits, llvh::makeArrayRef(src.digits, src.numDigits));

  if (sign) {
    
    tmp.negate();
  }

  std::string digits;

  
  
  
  digits.reserve(1 + src.numDigits * maxCharsPerDigitInRadix(radix));
  do {
    llvh::APInt quoc;
    uint64_t rem;
    llvh::APInt::udivrem(tmp, static_cast<uint64_t>(radix), quoc, rem);

    if (rem < 10) {
      digits.push_back('0' + rem);
    } else {
      digits.push_back('a' + rem - 10);
    }

    tmp = std::move(quoc);
  } while (tmp != 0);

  if (sign) {
    digits.push_back('-');
  }

  std::reverse(digits.begin(), digits.end());
  return digits;
}

OperationStatus toString(std::string &out, llvh::ArrayRef<uint8_t> bytes, uint8_t radix) {
  unsigned numDigits = numDigitsForSizeInBytes(bytes.size());
  if (tooManyDigits(numDigits)) {
    return OperationStatus::TOO_MANY_DIGITS;
  }

  TmpStorage tmp(numDigits);
  MutableBigIntRef dst{tmp.requestNumDigits(numDigits), numDigits};
  auto res = initWithBytes(dst, bytes);
  if (LLVM_UNLIKELY(res != OperationStatus::RETURNED)) {
    return res;
  }

  out = toString(ImmutableBigIntRef{dst.digits, dst.numDigits}, radix);
  return OperationStatus::RETURNED;
}

int compare(ImmutableBigIntRef lhs, ImmutableBigIntRef rhs) {
  const int kLhsGreater = 1;
  const int kRhsGreater = -kLhsGreater;

  const bool lhsSign = isNegative(lhs);
  const bool rhsSign = isNegative(rhs);

  
  
  
  if (lhsSign != rhsSign) {
    return lhsSign ? kRhsGreater : kLhsGreater;
  }

  int result;

  if (lhs.numDigits == rhs.numDigits) {
    
    result = llvh::APInt::tcCompare(lhs.digits, rhs.digits, lhs.numDigits);
  } else {
    
    
    
    
    if (lhsSign) {
      
      result = lhs.numDigits < rhs.numDigits ? kLhsGreater : kRhsGreater;
    } else {
      
      result = lhs.numDigits < rhs.numDigits ? kRhsGreater : kLhsGreater;
    }
  }

  return result;
}

namespace {









ImmutableBigIntRef makeImmutableRefFromSignedDigit( SignedBigIntDigitType &digit) {
  
  uint32_t numDigits = 1;
  MutableBigIntRef mr{reinterpret_cast<BigIntDigitType *>(&digit), numDigits};
  
  
  ensureCanonicalResult(mr);
  
  return ImmutableBigIntRef{
      reinterpret_cast<BigIntDigitType *>(&digit), numDigits};
}
} 

int compare(ImmutableBigIntRef lhs, SignedBigIntDigitType rhs) {
  
  return compare(lhs, makeImmutableRefFromSignedDigit(rhs));
}

bool isSingleDigitTruncationLossless( ImmutableBigIntRef src, bool signedTruncation) {

  if (src.numDigits == 0) {
    
    return true;
  }

  if (signedTruncation) {
    
    
    return src.numDigits == 1;
  }
  
  
  
  
  return (src.numDigits == 1 && src.digits[0] <= std::numeric_limits<int64_t>::max()) || (src.numDigits == 2 && src.digits[1] == 0);

}

namespace {

template <typename AnyBigIntRef> BigIntDigitType getBigIntRefSignExtValue(const AnyBigIntRef &src) {
  return src.numDigits == 0 ? static_cast<BigIntDigitType>(0)
      : getSignExtValue<BigIntDigitType>(src.digits[src.numDigits - 1]);
}



OperationStatus initNonCanonicalWithReadOnlyBigInt( MutableBigIntRef &dst, const ImmutableBigIntRef &src) {

  
  if (dst.numDigits < src.numDigits) {
    return OperationStatus::DEST_TOO_SMALL;
  }

  
  const uint32_t digitsToCopy = src.numDigits;
  const uint32_t bytesToCopy = digitsToCopy * BigIntDigitSizeInBytes;
  memcpy(dst.digits, src.digits, bytesToCopy);

  
  const uint32_t digitsToSet = dst.numDigits - digitsToCopy;
  const uint32_t bytesToSet = digitsToSet * BigIntDigitSizeInBytes;
  const BigIntDigitType signExtValue = getBigIntRefSignExtValue(src);
  memset(dst.digits + digitsToCopy, signExtValue, bytesToSet);

  return OperationStatus::RETURNED;
}
} 

OperationStatus asUintNResultSize(uint64_t n, ImmutableBigIntRef src, uint32_t &resultSize) {
  static_assert( BigIntMaxSizeInDigits < std::numeric_limits<uint32_t>::max(), "uint32_t is not large enough to represent max bigint digits.");


  const uint64_t numBitsSrc = src.numDigits * BigIntDigitSizeInBits;

  uint64_t numBitsResult;
  if (!isNegative(src)) {
    
    
    numBitsResult = std::min(n, numBitsSrc) + 1;
  } else {
    
    
    numBitsResult = n + 1;
  }

  if (numBitsResult > BigIntMaxSizeInBits) {
    return OperationStatus::TOO_MANY_DIGITS;
  }

  resultSize = numDigitsForSizeInBits(numBitsResult);
  return OperationStatus::RETURNED;
}

uint32_t asIntNResultSize(uint64_t n, ImmutableBigIntRef src) {
  static_assert( BigIntMaxSizeInDigits < std::numeric_limits<uint32_t>::max(), "uint32_t is not large enough to represent max bigint digits.");


  
  
  
  const uint64_t numDigitsN = numDigitsForSizeInBits(n);

  return std::min<uint64_t>(src.numDigits, numDigitsN);
}

namespace {
enum class BigIntAs { IntN, UintN };




















static OperationStatus bigintAsImpl( MutableBigIntRef dst, uint32_t numDigits, uint64_t n, ImmutableBigIntRef src, BigIntAs operation) {




  if (dst.numDigits < numDigits) {
    return OperationStatus::DEST_TOO_SMALL;
  }
  dst.numDigits = numDigits;

  
  
  
  if (src.numDigits == 0 || n == 0) {
    return initWithDigits(dst, src);
  }

  
  
  const uint64_t k = (n - 1) / BigIntDigitSizeInBits;
  const uint32_t bitWithinK = (n - 1) % BigIntDigitSizeInBits;

  
  
  
  
  
  assert( (k < dst.numDigits || !isNegative(src) || operation == BigIntAs::IntN) && "result is missing digits");


  
  
  
  
  
  const uint32_t numDigitsToCopy = std::min<uint64_t>(k + 1, src.numDigits);

  
  
  
  
  uint32_t numDigitsDst = std::min<uint64_t>(k + 1, dst.numDigits);
  MutableBigIntRef limitedDst{dst.digits, numDigitsDst};

  
  auto res = initNonCanonicalWithReadOnlyBigInt( limitedDst, ImmutableBigIntRef{src.digits, numDigitsToCopy});
  if (LLVM_UNLIKELY(res != OperationStatus::RETURNED)) {
    return res;
  }

  if (k < dst.numDigits) {
    
    const bool hasSign = operation == BigIntAs::IntN;

    
    
    
    
    
    const bool sign = hasSign && (dst.digits[k] & (1ull << bitWithinK)) != 0;

    if (bitWithinK < BigIntDigitSizeInBits - 1) {
      
      
      
      
      
      
      const BigIntDigitType signExtMask = llvh::maskTrailingZeros<BigIntDigitType>(bitWithinK + 1);

      if (sign) {
        dst.digits[k] |= signExtMask;
      } else {
        dst.digits[k] &= ~signExtMask;
      }
    }

    
    
    
    const uint32_t numDigitsToSet = (k + 1 < dst.numDigits) ? (dst.numDigits - k - 1) : 0;

    
    
    
    
    assert( (operation == BigIntAs::IntN || static_cast<SignedBigIntDigitType>(dst.digits[k]) >= 0 || dst.numDigits > k + 1) && "BigInt.asUintN will result in negative number.");




    
    memset( dst.digits + k + 1, sign ? 0xff : 0, numDigitsToSet * BigIntDigitSizeInBytes);


  }

  ensureCanonicalResult(dst);
  return OperationStatus::RETURNED;
}
} 

OperationStatus asUintN(MutableBigIntRef dst, uint64_t n, ImmutableBigIntRef src) {
  uint32_t numDigits;
  OperationStatus s = asUintNResultSize(n, src, numDigits);
  if (LLVM_UNLIKELY(s != OperationStatus::RETURNED)) {
    return s;
  }
  return bigintAsImpl(dst, numDigits, n, src, BigIntAs::UintN);
}

OperationStatus asIntN(MutableBigIntRef dst, uint64_t n, ImmutableBigIntRef src) {
  const uint32_t numDigits = asIntNResultSize(n, src);
  return bigintAsImpl(dst, numDigits, n, src, BigIntAs::IntN);
}

uint32_t unaryMinusResultSize(ImmutableBigIntRef src) {
  
  
  
  
  
  
  
  
  
  return !isNegative(src) ? src.numDigits : src.numDigits + 1;
}

OperationStatus unaryMinus(MutableBigIntRef dst, ImmutableBigIntRef src) {
  auto res = initNonCanonicalWithReadOnlyBigInt(dst, src);
  if (LLVM_UNLIKELY(res != OperationStatus::RETURNED)) {
    return res;
  }

  llvh::APInt::tcNegate(dst.digits, dst.numDigits);
  ensureCanonicalResult(dst);

  assert( ((isNegative(ImmutableBigIntRef{dst.digits, dst.numDigits}) != isNegative(src)) || compare(src, 0) == 0) && "unaryMinus overflow");



  return OperationStatus::RETURNED;
}

uint32_t unaryNotResultSize(ImmutableBigIntRef src) {
  
  
  return std::max(1u, src.numDigits);
}

OperationStatus unaryNot(MutableBigIntRef lhs, ImmutableBigIntRef rhs) {
  auto res = initNonCanonicalWithReadOnlyBigInt(lhs, rhs);
  if (LLVM_UNLIKELY(res != OperationStatus::RETURNED)) {
    return res;
  }

  llvh::APInt::tcComplement(lhs.digits, lhs.numDigits);
  ensureCanonicalResult(lhs);
  return OperationStatus::RETURNED;
}

namespace {
using AdditiveOp = BigIntDigitType (*)( BigIntDigitType *, const BigIntDigitType *, BigIntDigitType, unsigned);



using AdditiveOpPart = BigIntDigitType (*)(BigIntDigitType *, BigIntDigitType, unsigned);
using AdditiveOpPostProcess = void (*)(MutableBigIntRef &);

OperationStatus additiveOperation( AdditiveOp op, AdditiveOpPart opPart, AdditiveOpPostProcess opPost, MutableBigIntRef dst, ImmutableBigIntRef lhs, ImmutableBigIntRef rhs) {





  
  
  
  
  
  
  
  
  
  assert( lhs.numDigits <= rhs.numDigits && "lhs should have fewer digits than rhs");


  if (dst.numDigits < rhs.numDigits) {
    return OperationStatus::DEST_TOO_SMALL;
  }

  
  
  
  
  if (rhs.numDigits + 1 < dst.numDigits) {
    dst.numDigits = rhs.numDigits + 1;
  }

  
  auto res = initNonCanonicalWithReadOnlyBigInt(dst, lhs);
  if (LLVM_UNLIKELY(res != OperationStatus::RETURNED)) {
    return res;
  }

  
  const BigIntDigitType carryIn = 0;
  BigIntDigitType carryOut = (*op)(dst.digits, rhs.digits, carryIn, rhs.numDigits);
  (*opPart)( dst.digits + rhs.numDigits, carryOut + getBigIntRefSignExtValue(rhs), dst.numDigits - rhs.numDigits);



  
  (*opPost)(dst);

  
  ensureCanonicalResult(dst);
  return OperationStatus::RETURNED;
}

BigIntDigitType noopAdditiveOpPart(BigIntDigitType *, BigIntDigitType, unsigned numDigits) {
  assert( numDigits == 0 && "noop additive part was given digits; noop additive part is free!");

  return 0;
}

void noopAdditiveOpPostProcess(MutableBigIntRef &) {}

void negateAdditiveOpPostProcess(MutableBigIntRef &dst) {
  llvh::APInt::tcNegate(dst.digits, dst.numDigits);
}

template <auto Op> BigIntDigitType tcBitwiseWithCarry( BigIntDigitType *lhs, const BigIntDigitType *rhs, BigIntDigitType , uint32_t numDigits) {




  Op(lhs, rhs, numDigits);
  return 0;
}
} 

uint32_t bitwiseANDResultSize(ImmutableBigIntRef lhs, ImmutableBigIntRef rhs) {
  return std::max(lhs.numDigits, rhs.numDigits);
}

OperationStatus bitwiseAND( MutableBigIntRef dst, ImmutableBigIntRef lhs, ImmutableBigIntRef rhs) {


  
  const auto &[srcWithFewerDigits, srcWithMostDigits] = lhs.numDigits <= rhs.numDigits ? std::make_tuple(lhs, rhs)
                                     : std::make_tuple(rhs, lhs);

  return additiveOperation( tcBitwiseWithCarry<llvh::APInt::tcAnd>, noopAdditiveOpPart, noopAdditiveOpPostProcess, dst, srcWithFewerDigits, srcWithMostDigits);





}

uint32_t bitwiseORResultSize(ImmutableBigIntRef lhs, ImmutableBigIntRef rhs) {
  return std::max(lhs.numDigits, rhs.numDigits);
}

OperationStatus bitwiseOR( MutableBigIntRef dst, ImmutableBigIntRef lhs, ImmutableBigIntRef rhs) {


  
  const auto &[srcWithFewerDigits, srcWithMostDigits] = lhs.numDigits <= rhs.numDigits ? std::make_tuple(lhs, rhs)
                                     : std::make_tuple(rhs, lhs);

  return additiveOperation( tcBitwiseWithCarry<llvh::APInt::tcOr>, noopAdditiveOpPart, noopAdditiveOpPostProcess, dst, srcWithFewerDigits, srcWithMostDigits);





}

uint32_t bitwiseXORResultSize(ImmutableBigIntRef lhs, ImmutableBigIntRef rhs) {
  return std::max(lhs.numDigits, rhs.numDigits);
}

OperationStatus bitwiseXOR( MutableBigIntRef dst, ImmutableBigIntRef lhs, ImmutableBigIntRef rhs) {


  
  const auto &[srcWithFewerDigits, srcWithMostDigits] = lhs.numDigits <= rhs.numDigits ? std::make_tuple(lhs, rhs)
                                     : std::make_tuple(rhs, lhs);

  return additiveOperation( tcBitwiseWithCarry<llvh::APInt::tcXor>, noopAdditiveOpPart, noopAdditiveOpPostProcess, dst, srcWithFewerDigits, srcWithMostDigits);





}

uint32_t addResultSize(ImmutableBigIntRef lhs, ImmutableBigIntRef rhs) {
  
  
  
  
  return std::max(lhs.numDigits, rhs.numDigits) + 1;
}

OperationStatus add(MutableBigIntRef dst, ImmutableBigIntRef lhs, ImmutableBigIntRef rhs) {
  
  const auto &[srcWithFewerDigits, srcWithMostDigits] = lhs.numDigits <= rhs.numDigits ? std::make_tuple(lhs, rhs)
                                     : std::make_tuple(rhs, lhs);

  return additiveOperation( llvh::APInt::tcAdd, llvh::APInt::tcAddPart, noopAdditiveOpPostProcess, dst, srcWithFewerDigits, srcWithMostDigits);





}

uint32_t addSignedResultSize( ImmutableBigIntRef lhs, SignedBigIntDigitType sImm) {

  return addResultSize(lhs, makeImmutableRefFromSignedDigit(sImm));
}

OperationStatus addSigned( MutableBigIntRef dst, ImmutableBigIntRef lhs, SignedBigIntDigitType sImm) {


  return add(dst, lhs, makeImmutableRefFromSignedDigit(sImm));
}

uint32_t subtractResultSize(ImmutableBigIntRef lhs, ImmutableBigIntRef rhs) {
  
  
  
  
  return std::max(lhs.numDigits, rhs.numDigits) + 1;
}

OperationStatus subtract(MutableBigIntRef dst, ImmutableBigIntRef lhs, ImmutableBigIntRef rhs) {
  
  
  const auto &[srcWithFewerDigits, srcWithMostDigits, postProcess] = lhs.numDigits <= rhs.numDigits ? std::make_tuple(lhs, rhs, noopAdditiveOpPostProcess)

      : std::make_tuple(rhs, lhs, negateAdditiveOpPostProcess);

  return additiveOperation( llvh::APInt::tcSubtract, llvh::APInt::tcSubtractPart, postProcess, dst, srcWithFewerDigits, srcWithMostDigits);





}

uint32_t subtractSignedResultSize( ImmutableBigIntRef lhs, SignedBigIntDigitType sImm) {

  return subtractResultSize(lhs, makeImmutableRefFromSignedDigit(sImm));
}

OperationStatus subtractSigned( MutableBigIntRef dst, ImmutableBigIntRef lhs, SignedBigIntDigitType sImm) {


  return subtract(dst, lhs, makeImmutableRefFromSignedDigit(sImm));
}

uint32_t multiplyResultSize(ImmutableBigIntRef lhs, ImmutableBigIntRef rhs) {
  return (!lhs.numDigits || !rhs.numDigits) ? 0 : lhs.numDigits + rhs.numDigits + 1;
}

namespace {


std::tuple<OperationStatus, ImmutableBigIntRef> copyAndNegate( MutableBigIntRef dst, ImmutableBigIntRef src) {

  auto res = initNonCanonicalWithReadOnlyBigInt(dst, src);
  if (LLVM_UNLIKELY(res != OperationStatus::RETURNED)) {
    return std::make_tuple(res, ImmutableBigIntRef{});
  }

  
  llvh::APInt::tcNegate(dst.digits, dst.numDigits);

  
  ensureCanonicalResult(dst);

  
  return std::make_tuple( OperationStatus::RETURNED, ImmutableBigIntRef{dst.digits, dst.numDigits});
}
} 

OperationStatus multiply(MutableBigIntRef dst, ImmutableBigIntRef lhs, ImmutableBigIntRef rhs) {
  const uint32_t oldDstSize = multiplyResultSize(lhs, rhs);
  const bool isLhsNegative = isNegative(lhs);
  const bool isRhsNegative = isNegative(rhs);

  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  uint32_t tmpStorageSizeLhs = isLhsNegative ? lhs.numDigits : 0;
  uint32_t tmpStorageSizeRhs = isRhsNegative ? rhs.numDigits : 0;
  const uint32_t tmpStorageSize = tmpStorageSizeLhs + tmpStorageSizeRhs;

  
  TmpStorage tmpStorage(tmpStorageSize);

  if (isLhsNegative) {
    MutableBigIntRef tmp{
        tmpStorage.requestNumDigits(tmpStorageSizeLhs), tmpStorageSizeLhs};
    auto [res, newLhs] = copyAndNegate(tmp, lhs);
    if (LLVM_UNLIKELY(res != OperationStatus::RETURNED)) {
      return res;
    }
    lhs = newLhs;
  }

  if (isRhsNegative) {
    MutableBigIntRef tmp{
        tmpStorage.requestNumDigits(tmpStorageSizeRhs), tmpStorageSizeRhs};
    auto [res, newRhs] = copyAndNegate(tmp, rhs);
    if (LLVM_UNLIKELY(res != OperationStatus::RETURNED)) {
      return res;
    }
    rhs = newRhs;
  }

  
  
  const uint32_t dstSize = multiplyResultSize(lhs, rhs);
  assert( oldDstSize == dstSize && "multiplication result size can't change even if operands were negated.");

  (void)oldDstSize;

  if (dst.numDigits < dstSize) {
    return OperationStatus::DEST_TOO_SMALL;
  }

  
  dst.numDigits = dstSize;

  
  if (dstSize > 0) {
    
    
    llvh::APInt::tcFullMultiply( dst.digits, lhs.digits, rhs.digits, lhs.numDigits, rhs.numDigits);

    
    
    const uint32_t resultSize = lhs.numDigits + rhs.numDigits;
    memset( dst.digits + resultSize, 0, (dst.numDigits - resultSize) * BigIntDigitSizeInBytes);



    
    const bool negateResult = isLhsNegative != isRhsNegative;
    if (negateResult) {
      llvh::APInt::tcNegate(dst.digits, dst.numDigits);
    }
  }

  ensureCanonicalResult(dst);
  return OperationStatus::RETURNED;
}

namespace {
namespace div_rem {
static uint32_t getResultSize(ImmutableBigIntRef lhs, ImmutableBigIntRef rhs) {
  return std::max(lhs.numDigits, rhs.numDigits) + 1;
}

static OperationStatus compute( MutableBigIntRef quoc, MutableBigIntRef rem, ImmutableBigIntRef lhs, ImmutableBigIntRef rhs) {



  assert( ((quoc.digits != nullptr) != (rem.digits != nullptr)) && "untested -- calling with both or neither quoc and rem");


  const uint32_t resultSize = divideResultSize(lhs, rhs);
  
  
  if (quoc.digits == nullptr) {
    quoc.numDigits = resultSize;
  } else {
    rem.numDigits = resultSize;
  }

  
  if (quoc.numDigits < resultSize) {
    return OperationStatus::DEST_TOO_SMALL;
  }

  
  quoc.numDigits = resultSize;
  rem.numDigits = resultSize;

  
  if (compare(rhs, 0) == 0) {
    return OperationStatus::DIVISION_BY_ZERO;
  }

  
  
  
  const bool isLhsNegative = isNegative(lhs);
  const bool isRhsNegative = isNegative(rhs);

  
  const bool needToResizeRhs = rhs.numDigits < resultSize;

  
  
  const bool needTmpQuoc = quoc.digits == nullptr;
  const bool needTmpRem = rem.digits == nullptr;
  const bool needTmpRhs = isRhsNegative || needToResizeRhs;

  uint32_t tmpStorageSizeScratch = resultSize;
  uint32_t tmpStorageSizeQuoc = needTmpQuoc ? resultSize : 0;
  uint32_t tmpStorageSizeRem = needTmpRem ? resultSize : 0;
  uint32_t tmpStorageSizeRhs = needTmpRhs ? resultSize : 0;

  const uint32_t tmpStorageSize = tmpStorageSizeScratch + tmpStorageSizeQuoc + tmpStorageSizeRem + tmpStorageSizeRhs;

  TmpStorage tmpStorage(tmpStorageSize);

  BigIntDigitType *scratch = tmpStorage.requestNumDigits(tmpStorageSizeScratch);

  if (needTmpQuoc) {
    assert(quoc.numDigits == tmpStorageSizeQuoc);
    quoc.digits = tmpStorage.requestNumDigits(tmpStorageSizeQuoc);
  } else {
    assert(rem.numDigits == tmpStorageSizeRem);
    rem.digits = tmpStorage.requestNumDigits(tmpStorageSizeRem);
  }

  if (needTmpRhs) {
    MutableBigIntRef tmpRhs{
        tmpStorage.requestNumDigits(tmpStorageSizeRhs), tmpStorageSizeRhs};
    auto res = initNonCanonicalWithReadOnlyBigInt(tmpRhs, rhs);
    assert(res == OperationStatus::RETURNED && "temporary array is too small");
    (void)res;
    if (isRhsNegative) {
      llvh::APInt::tcNegate(tmpRhs.digits, tmpRhs.numDigits);
    }
    rhs = ImmutableBigIntRef{tmpRhs.digits, tmpRhs.numDigits};
  }

  
  
  
  
  auto res = initNonCanonicalWithReadOnlyBigInt(quoc, lhs);
  assert(res == OperationStatus::RETURNED && "quoc array is too small");
  (void)res;

  
  
  if (isLhsNegative) {
    llvh::APInt::tcNegate(quoc.digits, quoc.numDigits);
  }

  llvh::APInt::tcDivide( quoc.digits, rhs.digits, rem.digits, scratch, resultSize);

  
  
  if (!needTmpQuoc) {
    
    const bool negateQuoc = isLhsNegative != isRhsNegative;
    if (negateQuoc) {
      llvh::APInt::tcNegate(quoc.digits, quoc.numDigits);
    }
    ensureCanonicalResult(quoc);
  }

  
  
  if (!needTmpRem) {
    
    if (isLhsNegative) {
      llvh::APInt::tcNegate(rem.digits, rem.numDigits);
    }
    ensureCanonicalResult(rem);
  }

  return OperationStatus::RETURNED;
}
} 
} 

uint32_t divideResultSize(ImmutableBigIntRef lhs, ImmutableBigIntRef rhs) {
  return div_rem::getResultSize(lhs, rhs);
}

OperationStatus divide(MutableBigIntRef dst, ImmutableBigIntRef lhs, ImmutableBigIntRef rhs) {
  uint32_t numRemDigits = 0;
  MutableBigIntRef nullRem{nullptr, numRemDigits};
  return div_rem::compute(dst, nullRem, lhs, rhs);
}

uint32_t remainderResultSize(ImmutableBigIntRef lhs, ImmutableBigIntRef rhs) {
  return div_rem::getResultSize(lhs, rhs);
}

OperationStatus remainder( MutableBigIntRef dst, ImmutableBigIntRef lhs, ImmutableBigIntRef rhs) {


  uint32_t numQuocDigits = 0;
  MutableBigIntRef nullQuoc{nullptr, numQuocDigits};
  return div_rem::compute(nullQuoc, dst, lhs, rhs);
}

namespace {

static OperationStatus exponentiatePowerOf2( MutableBigIntRef dst, uint32_t exponent) {

  const uint32_t numDigitsResult = 1 + (exponent / BigIntDigitSizeInBits);
  const uint32_t numDigits = 1 + numDigitsResult;
  const uint32_t bitToSet = exponent % BigIntDigitSizeInBits;

  if (BigIntMaxSizeInDigits < numDigits) {
    return OperationStatus::TOO_MANY_DIGITS;
  }

  if (dst.numDigits < numDigits) {
    return OperationStatus::DEST_TOO_SMALL;
  }
  dst.numDigits = numDigits;

  
  
  BigIntDigitType dummyDigit[1];
  ImmutableBigIntRef zero{dummyDigit, 0};
  auto res = initNonCanonicalWithReadOnlyBigInt(dst, zero);
  if (LLVM_UNLIKELY(res != OperationStatus::RETURNED)) {
    return res;
  }
  
  dst.digits[numDigitsResult - 1] = 1ull << bitToSet;
  return OperationStatus::RETURNED;
}







class MutableBigIntAndMaxSize {
 public:
  
  
  MutableBigIntAndMaxSize(MutableBigIntRef &ref)
      : r(&ref), maxDigits(ref.numDigits) {}

   operator MutableBigIntRef &() {
    return ref();
  }

   operator ImmutableBigIntRef() const {
    return ImmutableBigIntRef{r->digits, r->numDigits};
  }

  void swap(MutableBigIntAndMaxSize &other) {
    std::swap(r, other.r);
    std::swap(maxDigits, other.maxDigits);
  }

  MutableBigIntRef &ref() {
    return *r;
  }

  void resetRefNumDigits() {
    r->numDigits = maxDigits;
  }

  uint32_t getMaxDigits() const {
    return maxDigits;
  }

 private:
  MutableBigIntRef *r;
  uint32_t maxDigits;
};




OperationStatus multiplyStatusToExponentiateStatus( OperationStatus status, uint32_t maxDigitsDst) {

  
  
  if (status == OperationStatus::DEST_TOO_SMALL && maxDigitsDst >= BigIntMaxSizeInDigits) {
    return OperationStatus::TOO_MANY_DIGITS;
  }

  
  return status;
}










OperationStatus exponentiateSlowPath( MutableBigIntRef dst, ImmutableBigIntRef lhs, uint32_t exponent) {


  
  
  
  
  
  
  uint32_t runningSquareSize0 = BigIntMaxSizeInDigits;
  uint32_t runningSquareSize1 = BigIntMaxSizeInDigits;
  uint32_t tmpResultTmpSize = BigIntMaxSizeInDigits;
  TmpStorage tmpBuffers( runningSquareSize0 + runningSquareSize1 + tmpResultTmpSize);
  MutableBigIntRef runningSquare0{
      tmpBuffers.requestNumDigits(runningSquareSize0), runningSquareSize0};
  MutableBigIntRef runningSquare1{
      tmpBuffers.requestNumDigits(runningSquareSize1), runningSquareSize1};

  
  
  
  
  
  

  MutableBigIntRef tmpResult{
      tmpBuffers.requestNumDigits(tmpResultTmpSize), tmpResultTmpSize};

  
  
  
  MutableBigIntAndMaxSize runningSquare = runningSquare0;
  MutableBigIntAndMaxSize tmpRunningSquare = runningSquare1;
  MutableBigIntAndMaxSize result = dst;
  MutableBigIntAndMaxSize nextResult = tmpResult;

  
  auto res = initWithDigits(runningSquare, lhs);
  if (LLVM_UNLIKELY(res != OperationStatus::RETURNED)) {
    return res;
  }

  
  if ((exponent & 1) == 0) {
    result.ref().numDigits = 0;
  } else {
    res = initWithDigits(result, lhs);
    if (LLVM_UNLIKELY(res != OperationStatus::RETURNED)) {
      return res;
    }
  }

  
  for (exponent >>= 1; exponent > 0; exponent >>= 1) {
    
    tmpRunningSquare.resetRefNumDigits();
    res = multiply(tmpRunningSquare, runningSquare, runningSquare);
    res = multiplyStatusToExponentiateStatus( res, tmpRunningSquare.getMaxDigits());
    tmpRunningSquare.swap(runningSquare);

    if (LLVM_UNLIKELY(res != OperationStatus::RETURNED)) {
      return res;
    }

    
    if ((exponent & 1) != 0) {
      nextResult.resetRefNumDigits();
      if (compare(result, 0) == 0) {
        res = initWithDigits(nextResult, runningSquare);
      } else {
        res = multiply(nextResult, result, runningSquare);
        res = multiplyStatusToExponentiateStatus(res, nextResult.getMaxDigits());
      }
      if (LLVM_UNLIKELY(res != OperationStatus::RETURNED)) {
        return res;
      }
      nextResult.swap(result);
    }
  }

  res = OperationStatus::RETURNED;
  if (&result.ref() != &dst) {
    nextResult.resetRefNumDigits();
    res = initNonCanonicalWithReadOnlyBigInt(nextResult, result);
  }

  return res;
}
} 

static_assert( static_cast<SignedBigIntDigitType>(BigIntMaxSizeInBits) > 0, "BigIntMaxSizeInBits overflow");


OperationStatus exponentiate( MutableBigIntRef dst, ImmutableBigIntRef lhs, ImmutableBigIntRef rhs) {


  if (compare(rhs, 0) < 0) {
    return OperationStatus::NEGATIVE_EXPONENT;
  }

  
  
  
  static constexpr auto maxExponent = BigIntMaxSizeInBits;
  const uint32_t exponent = rhs.numDigits ? rhs.digits[0] : 0;
  
  
  static_assert( maxExponent <= std::numeric_limits<decltype(exponent)>::max(), "exponent is too large");


  
  
  OperationStatus res = OperationStatus::RETURNED;
  if (compare(rhs, 0) == 0) {
    
    
    if (dst.numDigits < 1) {
      res = OperationStatus::DEST_TOO_SMALL;
    } else {
      dst.numDigits = 1;
      dst.digits[0] = 1;
    }
  } else if (compare(lhs, 0) == 0) {
    
    dst.numDigits = 0;
  } else if (dst.numDigits < 1) {
    
    
    res = OperationStatus::DEST_TOO_SMALL;
  } else if (compare(lhs, 1) == 0) {
    
    assert(rhs.numDigits > 0 && "should have handled 0n");
    dst.numDigits = 1;
    dst.digits[0] = 1;
  } else if (compare(lhs, -1) == 0) {
    
    assert(rhs.numDigits > 0 && "should have handled 0n");
    dst.numDigits = 1;
    
    dst.digits[0] = (exponent % 2 == 0) ? 1ull : -1ull;
  } else if (rhs.numDigits > 1 || exponent >= maxExponent) {
    
    res = OperationStatus::TOO_MANY_DIGITS;
  } else if (exponent == 1) {
    
    res = initWithDigits(dst, lhs);
  } else if (compare(lhs, 2) == 0) {
    
    res = exponentiatePowerOf2(dst, exponent);
  } else if (compare(lhs, -2) == 0) {
    
    res = exponentiatePowerOf2(dst, exponent);
    if (exponent % 2 != 0) {
      llvh::APInt::tcNegate(dst.digits, dst.numDigits);
    }
  } else {
    
    res = exponentiateSlowPath(dst, lhs, exponent);
  }

  if (LLVM_UNLIKELY(res != OperationStatus::RETURNED)) {
    return res;
  }

  ensureCanonicalResult(dst);
  return OperationStatus::RETURNED;
}

namespace {
using IsRightShiftFn = bool (*)(ImmutableBigIntRef);
using GetShiftAmntFn = uint32_t (*)(ImmutableBigIntRef);





enum class ShiftOpIs { Left, Right };

static uint32_t shiftResultSizeImpl( ShiftOpIs shiftOp, ImmutableBigIntRef lhs, uint32_t shiftAmnt) {


  uint32_t extraDigits = 0;
  if (shiftOp == ShiftOpIs::Left) {
    
    
    extraDigits = numDigitsForSizeInBits(shiftAmnt);
  }

  const uint32_t result = lhs.numDigits + extraDigits;
  assert(extraDigits <= result && "too many digits in result");
  return result;
}

static constexpr SignedBigIntDigitType MaxPositiveShiftAmountInBits = BigIntMaxSizeInBits;

static constexpr SignedBigIntDigitType MinNegativeShiftAmountInBits = -static_cast<SignedBigIntDigitType>(BigIntMaxSizeInBits);



static_assert( 1 + MaxPositiveShiftAmountInBits < std::numeric_limits<uint32_t>::max(), "non negative shift amounts don't fit uint32_t");

static_assert( 1 + MinNegativeShiftAmountInBits > std::numeric_limits<int32_t>::min(), "non negative shift amounts don't fit int32_t");








static std::tuple<uint32_t, bool> getShiftAmountAndSign( ImmutableBigIntRef shiftAmnt) {
  
  
  
  
  
  const BigIntDigitType reallyLargeShiftAmount = numDigitsForSizeInBytes(MaxPositiveShiftAmountInBits + 1);

  const bool shiftAmntIsNeg = isNegative(shiftAmnt);

  if (compare(shiftAmnt, MinNegativeShiftAmountInBits) < 0 || compare(shiftAmnt, MaxPositiveShiftAmountInBits) > 0) {
    
    
    
    return std::make_tuple( static_cast<uint32_t>(reallyLargeShiftAmount), shiftAmntIsNeg);
  }

  const SignedBigIntDigitType sa = (shiftAmnt.numDigits == 0)
      ? 0ll : static_cast<SignedBigIntDigitType>(shiftAmnt.digits[0]);
  assert( (shiftAmnt.numDigits == 0 || shiftAmnt.digits[0] != std::numeric_limits<BigIntDigitType>::min()) && "shiftAmnt is MIN_INT, hence -signedShiftAmnt is MIN_INT");


  
  return std::make_tuple( static_cast<uint32_t>(shiftAmntIsNeg ? -sa : sa), shiftAmntIsNeg);
}

} 

uint32_t leftShiftResultSize(ImmutableBigIntRef lhs, ImmutableBigIntRef rhs) {
  const auto &[shiftAmnt, isNegative] = getShiftAmountAndSign(rhs);
  const auto shiftOp = isNegative ? ShiftOpIs::Right : ShiftOpIs::Left;
  return shiftResultSizeImpl(shiftOp, lhs, shiftAmnt);
}

uint32_t signedRightShiftResultSize( ImmutableBigIntRef lhs, ImmutableBigIntRef rhs) {

  const auto &[shiftAmnt, isNegative] = getShiftAmountAndSign(rhs);
  const auto shiftOp = isNegative ? ShiftOpIs::Left : ShiftOpIs::Right;
  return shiftResultSizeImpl(shiftOp, lhs, shiftAmnt);
}

namespace {
static std::tuple<uint32_t, ShiftOpIs, uint32_t> getShiftAmountSignAndResultSize( ShiftOpIs shiftOp, ImmutableBigIntRef lhs, ImmutableBigIntRef rhs) {



  const auto &[shiftAmnt, isNegative] = getShiftAmountAndSign(rhs);
  const auto actualShiftOp = (shiftOp == ShiftOpIs::Left) == isNegative ? ShiftOpIs::Right : ShiftOpIs::Left;


  return std::make_tuple( shiftAmnt, actualShiftOp, shiftResultSizeImpl(actualShiftOp, lhs, shiftAmnt));


}


















void signedRightShiftAdapter( BigIntDigitType *digits, uint32_t numDigits, uint32_t shiftAmnt) {


  const bool dstNegative = isNegative(ImmutableBigIntRef{digits, numDigits});

  if (dstNegative) {
    llvh::APInt::tcComplement(digits, numDigits);
  }

  llvh::APInt::tcShiftRight(digits, numDigits, shiftAmnt);

  if (dstNegative) {
    llvh::APInt::tcComplement(digits, numDigits);
  }
}


OperationStatus shiftImpl( ShiftOpIs shiftOp, MutableBigIntRef dst, ImmutableBigIntRef lhs, ImmutableBigIntRef rhs) {



  auto [shiftAmnt, actualShiftOp, numDigits] = getShiftAmountSignAndResultSize(shiftOp, lhs, rhs);
  auto op = (actualShiftOp == ShiftOpIs::Right) ? signedRightShiftAdapter : llvh::APInt::tcShiftLeft;

  if (dst.numDigits < numDigits) {
    return OperationStatus::DEST_TOO_SMALL;
  }

  auto res = initNonCanonicalWithReadOnlyBigInt(dst, lhs);
  if (LLVM_UNLIKELY(res != OperationStatus::RETURNED)) {
    return res;
  }

  (*op)(dst.digits, dst.numDigits, shiftAmnt);

  ensureCanonicalResult(dst);
  return OperationStatus::RETURNED;
}
} 

OperationStatus leftShift( MutableBigIntRef dst, ImmutableBigIntRef lhs, ImmutableBigIntRef rhs) {


  return shiftImpl(ShiftOpIs::Left, dst, lhs, rhs);
}

OperationStatus signedRightShift( MutableBigIntRef dst, ImmutableBigIntRef lhs, ImmutableBigIntRef rhs) {


  return shiftImpl(ShiftOpIs::Right, dst, lhs, rhs);
}

std::vector<BigIntTableEntry> UniquingBigIntTable::getEntryList() const {
  std::vector<BigIntTableEntry> result;
  result.reserve(bigints_.size());
  uint32_t offset = 0;
  for (const ParsedBigInt &bigint : bigints_) {
    const uint32_t size = bigint.getBytes().size();
    result.push_back(BigIntTableEntry{offset, size});
    offset += size;
  }
  return result;
}

BigIntBytes UniquingBigIntTable::getDigitsBuffer() const {
  BigIntBytes result;
  for (const ParsedBigInt &bigint : bigints_) {
    auto bytes = bigint.getBytes();
    result.insert(result.end(), bytes.begin(), bytes.end());
  }
  return result;
}

} 
} 
