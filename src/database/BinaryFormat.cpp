#include <BinaryFormat.hpp>

void Instruction::serialize(std::ostream &out) const
{
    out.write(reinterpret_cast<const char*>(&_address), sizeof(_address));

    uint32_t bytesSize = _bytes.size();
    out.write(reinterpret_cast<const char*>(&bytesSize), sizeof(bytesSize));
    out.write(reinterpret_cast<const char*>(_bytes.data()), bytesSize);

    uint32_t mnemonicSize = _mnemo.size();
    out.write(reinterpret_cast<const char*>(&mnemonicSize), sizeof(mnemonicSize));
    out.write(_mnemo.data(), mnemonicSize);

    serializeOperands(_op, out);
}

void Instruction::serializeOperands(const std::vector<std::string>& operands, std::ostream& out) const
{
    uint32_t numOperands = operands.size();
    out.write(reinterpret_cast<const char*>(&numOperands), sizeof(numOperands));

    for (const auto& operand : operands) {
        uint32_t operandSize = operand.size();
        out.write(reinterpret_cast<const char*>(&operandSize), sizeof(operandSize));
        out.write(operand.data(), operandSize);
    }
}

void Instruction::deserialize(std::istream &in)
{
    in.read(reinterpret_cast<char*>(&_address), sizeof(_address));

    uint32_t bytesSize;
    in.read(reinterpret_cast<char*>(&bytesSize), sizeof(bytesSize));
    _bytes.resize(bytesSize);
    in.read(reinterpret_cast<char*>(_bytes.data()), bytesSize);

    uint32_t mnemonicSize;
    in.read(reinterpret_cast<char*>(&mnemonicSize), sizeof(mnemonicSize));
    _mnemo.resize(mnemonicSize);
    in.read(_mnemo.data(), mnemonicSize);

    deserializeOperands(in);
}

void Instruction::deserializeOperands(std::istream &in)
{
    try {
    uint32_t numOperands;
    in.read(reinterpret_cast<char*>(&numOperands), sizeof(numOperands));
    //std::cout << "Number of operands: " << numOperands << std::endl;
    _op.resize(numOperands);
    for (auto &operand: _op) {
        uint32_t operandSize;
        in.read(reinterpret_cast<char*>(&operandSize), sizeof(operandSize));
        operand.resize(operandSize);
        in.read(operand.data(), operandSize);
    }
    } catch (std::bad_alloc &ba) {
    }
}

void Symbol::serialize(std::ostream &out) const
{
    out.write(reinterpret_cast<const char*>(&_address), sizeof(_address));

    uint32_t nameLength = _name.size();
    out.write(reinterpret_cast<const char*>(&nameLength), sizeof(nameLength));
    out.write(_name.data(), nameLength);

    out.write(reinterpret_cast<const char*>(&_type), sizeof(_type));
}

void Symbol::deserialize(std::istream &in)
{
    in.read(reinterpret_cast<char*>(&_address), sizeof(_address));

    uint32_t nameLength;
    in.read(reinterpret_cast<char*>(&nameLength), sizeof(nameLength));
    _name.resize(nameLength);
    in.read(_name.data(), nameLength);
    in.read(reinterpret_cast<char*>(&_type), sizeof(_type));
}

void CrossReference::serialize(std::ostream &out) const
{
    out.write(reinterpret_cast<const char*>(&_fromAddress), sizeof(_fromAddress));
    out.write(reinterpret_cast<const char*>(&_toAddress), sizeof(_toAddress));
    out.write(reinterpret_cast<const char*>(&_type), sizeof(_type));
}

void CrossReference::deserialize(std::istream &in)
{
    in.read(reinterpret_cast<char*>(&_fromAddress), sizeof(_fromAddress));
    in.read(reinterpret_cast<char*>(&_toAddress), sizeof(_toAddress));
    in.read(reinterpret_cast<char*>(&_type), sizeof(_type));
}
