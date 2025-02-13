#include <database/database.hpp>
#include <fstream>
#include <filesystem>
#include <format>

void FileHeader::serialize(std::ostream &out) const
{
    out.write(reinterpret_cast<const char*>(&instructionSize), sizeof(instructionSize));
    out.write(reinterpret_cast<const char*>(&instructionOffset), sizeof(instructionOffset));
    out.write(reinterpret_cast<const char*>(&symbolSize), sizeof(symbolSize));
    out.write(reinterpret_cast<const char*>(&symbolOffset), sizeof(symbolOffset));
    out.write(reinterpret_cast<const char*>(&xrefSize), sizeof(xrefSize));
    out.write(reinterpret_cast<const char*>(&xrefOffset), sizeof(xrefOffset));
}

void FileHeader::deserialize(std::istream &in)
{
    in.read(reinterpret_cast<char*>(&instructionSize), sizeof(instructionSize));
    in.read(reinterpret_cast<char*>(&instructionOffset), sizeof(instructionOffset));
    in.read(reinterpret_cast<char*>(&symbolSize), sizeof(symbolSize));
    in.read(reinterpret_cast<char*>(&symbolOffset), sizeof(symbolOffset));
    in.read(reinterpret_cast<char*>(&xrefSize), sizeof(xrefSize));
    in.read(reinterpret_cast<char*>(&xrefOffset), sizeof(xrefOffset));
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

void Database::createProject(const std::string &path) {
    _path = path;
    std::filesystem::path p = _path;
    if (std::filesystem::exists(p)) {
        std::cout << "Project already exist" << p << std::endl;
    } else {
        std::filesystem::create_directory(_path);
    }
}

void Database::serialize() const
{
    std::filesystem::path p = _path;
    if (!std::filesystem::exists(p)) {
        std::cout << "Project does not exists" << p << std::endl;
    }
    std::ofstream out(std::format("{}/1.db", _path), std::ios::binary);
    if (!out)
        throw std::runtime_error("Failed to open file for writing");
    FileHeader fHeader;

    std::streampos headerPos = out.tellp();
    out.seekp(sizeof(FileHeader), std::ios::cur);

    _binary->metadata->serialize(out);
    serializeData(_instructions, out, fHeader.instructionOffset, fHeader.instructionSize);
    serializeData(_symbols, out, fHeader.symbolOffset, fHeader.symbolSize);
    serializeData(_xrefs, out, fHeader.xrefOffset, fHeader.xrefSize);

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

Database Database::deserialize(const std::string &filepath, std::unique_ptr<Binary> &binary)
{
    std::filesystem::path p = filepath;
    if (!std::filesystem::exists(p)) {
        std::cout << "Project does not exist: " << p << std::endl;
    }
    std::ifstream in(std::format("{}/1.db", filepath), std::ios::binary);
    if (!in)
        throw std::runtime_error("Failed to open file for reading");
    FileHeader fHeader;
    fHeader.deserialize(in);

    binary = std::make_unique<Binary>(in);

    Database db(binary);
    deserializeData(db._instructions, in, fHeader.instructionOffset, fHeader.instructionSize);
    deserializeData(db._symbols, in, fHeader.symbolOffset, fHeader.symbolSize);
    deserializeData(db._xrefs, in, fHeader.xrefOffset, fHeader.xrefSize);
    in.close();

    return db;
}

/*void print_db(Database db)
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

int main(void)
{
    Header header("TestProject", "1.0.0");
    Database db(header);

    db.addInstruction(Instruction(0x1000, {0x48, 0x89}, "mov", {"rax", "rbp"}));
    db.addInstruction(Instruction(0x1000, {0x41, 0x80}, "mov", {"rax", "rax"}));
    db.addSymbol(Function(0x1000, 0x2000, "not_main", {"int", "string"}, "int"));
    print_db(db);
    db.serialize("project.db");

    std::cout << "____________\n";
    Database newDb = Database::deserialize("project.db");
    print_db(newDb);

    return 0;
}
*/
