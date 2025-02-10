#include <database/Symbol.hpp>

void Function::serialize(std::ostream &out) const
{
    out.write(reinterpret_cast<const char*>(&_startAddress), sizeof(_startAddress));
    out.write(reinterpret_cast<const char*>(&_endAddress), sizeof(_endAddress));

    uint32_t nameLength = _name.size();
    out.write(reinterpret_cast<const char*>(&nameLength), sizeof(nameLength));
    out.write(_name.data(), nameLength);

    uint32_t returnTypeLength = _returnType.size();
    out.write(reinterpret_cast<const char*>(&returnTypeLength), sizeof(returnTypeLength));
    out.write(_returnType.data(), returnTypeLength);

    Instruction::serializeOperands(_parameters, out);

    out.write(reinterpret_cast<const char*>(&_type), sizeof(_type));
}

void Function::deserialize(std::istream &in)
{
    in.read(reinterpret_cast<char*>(&_startAddress), sizeof(_startAddress));
    in.read(reinterpret_cast<char*>(&_endAddress), sizeof(_endAddress));

    uint32_t nameLength;
    in.read(reinterpret_cast<char*>(&nameLength), sizeof(nameLength));
    _name.resize(nameLength);
    in.read(_name.data(), nameLength);

    uint32_t returnTypeLength;
    in.read(reinterpret_cast<char*>(&returnTypeLength), sizeof(returnTypeLength));
    _returnType.resize(returnTypeLength);
    in.read(_returnType.data(), returnTypeLength);

    Instruction::deserializeOperands(_parameters, in);

    in.read(reinterpret_cast<char*>(&_type), sizeof(_type));
}
