#ifndef BINARYFORMAT_HPP
#define BINARYFORMAT_HPP

#include <cstdint>
#include <string>
#include <vector>
#include <iostream>

typedef enum: uint8_t {
    function = 0x01,
    variable = 0x02,
    call = 0x03,
    data = 0x04
} DataType;

class Metadata {
   public:
    explicit Metadata() {};
    virtual ~Metadata() = default;

    virtual void serialize(std::ostream &out) const = 0;
    virtual void deserialize(std::istream &in) = 0;
};

class IDataType: public Metadata {
   public:
    explicit IDataType(DataType type): _type(type) {};
    virtual ~IDataType() = default;
    virtual void serialize(std::ostream &out) const = 0;
    virtual void deserialize(std::istream &in) = 0;
    virtual void print() const = 0;
    std::string getTypeString() const {
        switch (_type) {
            case function:
                return "Function";
            case variable:
                return "Variable";
            case call:
                return "Call";
            case data:
                return "Data";
            default:
                return "";
        }
    }

   protected:
    DataType _type;
};

class Instruction: public Metadata {
   public:
    Instruction(uint64_t addr, const std::vector<uint8_t> bytes,
        const std::string &mnemo, const std::vector<std::string> op)
        : _address(addr), _bytes(bytes), _mnemo(mnemo), _op(op) {}
    ~Instruction() {};

    void serialize(std::ostream &out) const override;
    void deserialize(std::istream &in) override;

    void print() const {
        std::cout << "Address: 0x" << std::hex << _address << "\nMnemonic: " << _mnemo << "\nOperands: ";
        for (const auto& op : _op) std::cout << op << " ";
        std::cout << "\n";
    }

    static void serializeOperands(const std::vector<std::string>& operands, std::ostream& out);
    static void deserializeOperands(std::vector<std::string> &,std::istream &in);
   private:
    uint64_t _address;
    std::vector<uint8_t> _bytes;
    std::string _mnemo;
    std::vector<std::string> _op;

};

class Symbol: public IDataType {
   public:
    Symbol(uint64_t addr, const std::string &name, DataType type)
        : IDataType(type), _address(addr), _name(name) {}
    ~Symbol() {};
    uint64_t getAddress() const {return _address;};
    std::string getName() const {return _name;};

    void serialize(std::ostream &out) const override;
    void deserialize(std::istream &in) override;

    void print() const override {
        std::cout << "Symbol: " << _name << " at 0x" << std::hex << _address
                  << " [" << getTypeString() << "]\n";
    };

   private:
    uint64_t _address;

   public:
    std::string _name;
};

class CrossReference: public IDataType {
   public:
    CrossReference(uint64_t fromAddress, uint64_t toAddress, DataType type)
        : IDataType(type), _fromAddress(fromAddress), _toAddress(toAddress) {};
    ~CrossReference() {};
    void serialize(std::ostream &out) const override;
    void deserialize(std::istream &in) override;

    uint64_t getFromAddress() { return _fromAddress;};
    uint64_t getToAddress() { return _toAddress;};

    void print() const override {

    }
   private:
    uint64_t _fromAddress;
    uint64_t _toAddress;
};

#endif  // BINARYFORMAT_HPP
