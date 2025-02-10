#include <database/database.hpp>
#include <fstream>

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

void Header::serialize(std::ostream &out) const
{
    serializePairs(this->general_infos, out);
    serializePairs(this->file_headers, out);
    serializePairs(this->dos_headers, out);
}

Header Header::deserialize(std::istream &in)
{
    Header header;

    deserializePairs(this->general_infos, in);
    deserializePairs(this->file_headers, in);
    deserializePairs(this->dos_headers, in);

    return header;
}

void serializePairs(std::vector<std::pair<std::string, std::string>> metadata_vector, std::ostream &out)
{
    uint32_t numPairs = metadata_vector.size();
    out.write(reinterpret_cast<const char*>(&numPairs), sizeof(numPairs));

    for (const auto &pair : metadata_vector) {
        uint32_t firstStringSize = pair.first.size();
        out.write(reinterpret_cast<const char*>(&firstStringSize), sizeof(firstStringSize));
        out.write(pair.first.data(), firstStringSize);
        uint32_t secondStringSize = pair.first.size();
        out.write(reinterpret_cast<const char*>(&secondStringSize), sizeof(secondStringSize));
        out.write(pair.second.data(), secondStringSize);
    }
}

void deserializePairs(std::vector<std::pair<std::string, std::string>> &metadata_vector, std::istream &in)
{
    try {
        uint32_t numPairs;
        in.read(reinterpret_cast<char*>(&numPairs), sizeof(numPairs));
        //std::cout << "Number of operands: " << numOperands << std::endl;
        metadata_vector.resize(numPairs);
        for (auto &pair: metadata_vector) {
            uint32_t firstStringSize;
            in.read(reinterpret_cast<char*>(&firstStringSize), sizeof(firstStringSize));
            pair.first.resize(firstStringSize);
            in.read(pair.first.data(), firstStringSize);

            uint32_t secondStringSize;
            in.read(reinterpret_cast<char*>(&secondStringSize), sizeof(secondStringSize));
            pair.second.resize(secondStringSize);
            in.read(pair.second.data(), secondStringSize);
        }
    } catch (std::bad_alloc &ba) {}
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

    std::streampos headerPos = out.tellp();
    out.seekp(sizeof(FileHeader), std::ios::cur);

    _metadata.serialize(out);
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

Database Database::deserialize(const std::string &filepath)
{
    std::ifstream in(filepath, std::ios::binary);
    if (!in)
        throw std::runtime_error("Failed to open file for reading");
    FileHeader fHeader;
    fHeader.deserialize(in);

    Header metadata(in);
    Database db(metadata);

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
