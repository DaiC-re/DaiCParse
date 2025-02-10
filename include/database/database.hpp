#ifndef DATABASE_HPP
#define DATABASE_HPP

#include <vector>
#include <database/BinaryFormat.hpp>
#include <database/Symbol.hpp>

class Header {
   private:
    std::vector<std::pair<std::string, std::string>> general_infos;
    std::vector<std::pair<std::string, std::string>> file_headers;
    std::vector<std::pair<std::string, std::string>> dos_headers;

   public:
    Header() {};
    Header(std::istream &in) { deserialize(in); }
    ~Header() {}

    void serialize(std::ostream &out) const;
    void serializePairs(std::vector<std::pair<std::string, std::string>>, std::ostream &out) const;

    Header deserialize(std::istream &in);
    void deserializePairs(std::vector<std::pair<std::string, std::string>> &, std::istream &in);
};

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
    Header _metadata;
    std::vector<Instruction> _instructions;
    std::vector<Symbol> _symbols;
    std::vector<CrossReference> _xrefs;

   public:
    Database(Header metadata): _metadata(metadata) {};
    ~Database() {}

    Header getMetadata() const { return _metadata;};
    std::vector<Instruction> getInstructions() const { return _instructions;}

    std::vector<Symbol> getSymbols() const { return _symbols;}

    std::vector<CrossReference> getXRefs() const { return _xrefs;}

    void addInstruction(const Instruction &instr) { _instructions.push_back(instr);};
    void addSymbol(const Symbol &sym) { _symbols.push_back(sym);};
    void addXRefs(const CrossReference &xref) { _xrefs.push_back(xref);};

    void serialize(const std::string &filepath) const;
    template <typename Data>
    void serializeData(Data &datas, std::ostream &out, uint64_t &offset, uint64_t &size) const;

    static Database deserialize(const std::string &filepath);
    template <typename Data>
    static void deserializeData(std::vector<Data> &datas, std::istream &in, uint64_t &offset, uint64_t &size);
};

#endif  // DATABASE_HPP
