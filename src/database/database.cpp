#include "database.hpp"
#include <fstream>

void FileHeader::serialize(std::ostream &out) const
{
    out.write(reinterpret_cast<const char*>(&projectNameSize), sizeof(projectNameSize));
    out.write(reinterpret_cast<const char*>(&versionSize), sizeof(versionSize));
    out.write(reinterpret_cast<const char*>(&instructionSize), sizeof(instructionSize));
    out.write(reinterpret_cast<const char*>(&instructionOffset), sizeof(instructionOffset));
    out.write(reinterpret_cast<const char*>(&symbolSize), sizeof(symbolSize));
    out.write(reinterpret_cast<const char*>(&symbolOffset), sizeof(symbolOffset));
}

void FileHeader::deserialize(std::istream &in)
{
    in.read(reinterpret_cast<char*>(&projectNameSize), sizeof(projectNameSize));
    in.read(reinterpret_cast<char*>(&versionSize), sizeof(versionSize));
    in.read(reinterpret_cast<char*>(&instructionSize), sizeof(instructionSize));
    in.read(reinterpret_cast<char*>(&instructionOffset), sizeof(instructionOffset));
    in.read(reinterpret_cast<char*>(&symbolSize), sizeof(symbolSize));
    in.read(reinterpret_cast<char*>(&symbolOffset), sizeof(symbolOffset));
}

void Header::serialize(std::ostream &out) const
{
    uint32_t projectNameSize = _projectName.size();
    uint32_t versionSize = _version.size();

    out.write(_projectName.data(), projectNameSize);
    out.write(_version.data(), versionSize);
}

Header Header::deserialize(std::istream &in, uint32_t projectNameSize, uint32_t versionSize)
{
    Header header;
    header._projectName.resize(projectNameSize);
    header._version.resize(versionSize);
    in.read(header._projectName.data(), projectNameSize);
    in.read(header._version.data(), versionSize);
    return header;
}

template <typename Data>
void Database::serializeData(Data &datas, std::ostream &out, uint64_t &offset, uint64_t &size) const
{
    offset = out.tellp();
    size = 0;
    for (const auto &data: datas) {
        std::streampos start = out.tellp();
        data.serialize(out);
        size += out.tellp() - start;
    }
}

void Database::serialize(const std::string &filepath) const
{
    std::ofstream out(filepath, std::ios::binary);
    if (!out)
        throw std::runtime_error("Failed to open file for writing");
    FileHeader fHeader;
    fHeader.projectNameSize = _metadata.getProjectName().size();
    fHeader.versionSize = _metadata.getVersion().size();

    std::streampos headerPos = out.tellp();
    out.seekp(sizeof(FileHeader), std::ios::cur);

    _metadata.serialize(out);
    serializeData(_instructions, out, fHeader.instructionOffset, fHeader.instructionSize);
    serializeData(_symbols, out, fHeader.symbolOffset, fHeader.symbolSize);

    out.seekp(headerPos);
    fHeader.serialize(out);
    out.close();
}

template <typename Data>
void Database::deserializeData(std::vector<Data> &datas, std::istream &in, uint64_t &offset, uint64_t &size)
{
    in.seekg(offset);
    std::streampos endData = offset + size;
    while (in.tellg() < endData) {
        Data data;
        data.deserialize(in);
        datas.push_back(data);
    }
}

Database Database::deserialize(const std::string &filepath)
{
    std::ifstream in(filepath, std::ios::binary);
    if (!in)
        throw std::runtime_error("Failed to open file for reading");
    FileHeader fHeader;
    fHeader.deserialize(in);

    Database db(Header::deserialize(in, fHeader.projectNameSize, fHeader.versionSize));

    deserializeData(db._instructions, in, fHeader.instructionOffset, fHeader.instructionSize);
    deserializeData(db._symbols, in, fHeader.symbolOffset, fHeader.symbolSize);
    in.close();

    return db;
}

void print_db(Database db)
{
    std::cout << "Project: " << db.getMetadata().getProjectName() << "\nVersion: " <<db.getMetadata().getVersion() << "\n";
    std::cout << "\nInstructions:\n";
    for (const auto& instr : db.getInstructions()) {
        instr.print();
    }
    std::cout << "\nSymbols:\n";
    for (const auto& sym : db.getSymbols()) {
        sym.print();
    }
}
/*
int main(void)
{
    Header header("TestProject", "1.0.0");
    Database db(header);

    db.addInstruction(Instruction(0x1000, {0x48, 0x89}, "mov", {"rax", "rbp"}));
    db.addInstruction(Instruction(0x1000, {0x41, 0x80}, "mov", {"rax", "rax"}));
    db.addSymbol(Symbol(0x1000, "main", DataType::Function));
    print_db(db);
    db.serialize("project.db");

    std::cout << "____________\n";
    Database newDb = Database::deserialize("project.db");
    print_db(newDb);

    return 0;
}
*/
