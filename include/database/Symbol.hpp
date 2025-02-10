#ifndef SYMBOL_HPP
#define SYMBOL_HPP

#include <database/BinaryFormat.hpp>

class Function : public Symbol {
   public:
    Function() {};
    Function(uint64_t startAddress, uint64_t endAddress,
             std::string name, std::vector<std::string> parameters, std::string returnType)
        : _startAddress(startAddress), _endAddress(endAddress), _name(name), _parameters(parameters), _returnType(returnType){};
    ~Function() {};

    uint64_t getStartAddress() const { return _startAddress;}
    uint64_t getEndAddress() const { return _endAddress;}
    std::string getReturnType() const { return _returnType;}
    std::vector<std::string> getParameters() const { return _parameters;}

    void serialize(std::ostream &out) const override;
    void deserialize(std::istream &in) override;

    void print() const final {
        std::cout << "Function: " << _name << " at 0x" << std::hex << _startAddress
                  << " [" << getTypeString() << "]\n";
    };

   private:
    uint64_t _startAddress;
    uint64_t _endAddress;
    std::string _name;
    std::vector<std::string> _parameters;
    std::string _returnType;
    DataType _type = DataType::function;
};


#endif  // SYMBOL_HPP
