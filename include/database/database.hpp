#ifndef DATABASE_HPP
#define DATABASE_HPP

#include <vector>
#include <database/BinaryFormat.hpp>
#include <database/Symbol.hpp>
#include <metadata/metadata.hpp>
#include <binary/binary.hpp>

struct FileHeader {
    // Binary
    uint64_t instructionOffset;
    uint64_t instructionSize;
    uint64_t symbolOffset;
    uint64_t symbolSize;
    uint64_t xrefOffset;
    uint64_t xrefSize;

    void serialize(std::ostream &out) const;
    void deserialize(std::istream &in);
};

class Database {
   private:
    std::unique_ptr<Binary> &_binary;
    std::vector<Instruction> _instructions;
    std::vector<Symbol> _symbols;
    std::vector<CrossReference> _xrefs;

    std::string _path;
   public:
    Database(std::unique_ptr<Binary> &binary): _binary(binary) {};
    ~Database() {}

    std::unique_ptr<BinaryMetadata> &getMetadata() const { return _binary->metadata;};
    std::vector<Instruction> getInstructions() const { return _instructions;}

    std::vector<Symbol> getSymbols() const { return _symbols;}

    std::vector<CrossReference> getXRefs() const { return _xrefs;}

    void createProject(const std::string &path);
    void addInstruction(const Instruction &instr) { _instructions.push_back(instr);};
    void addSymbol(const Symbol &sym) { _symbols.push_back(sym);};
    void addXRefs(const CrossReference &xref) { _xrefs.push_back(xref);};

    void serialize() const;
    template <typename Data>
    void serializeData(Data &datas, std::ostream &out, uint64_t &offset, uint64_t &size) const;

    static Database deserialize(const std::string &filepath, std::unique_ptr<Binary> &binary);

    template <typename Data>
    static void deserializeData(std::vector<Data> &datas, std::istream &in, uint64_t &offset, uint64_t &size);
};

#endif  // DATABASE_HPP
