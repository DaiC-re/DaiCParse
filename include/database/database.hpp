#ifndef DATABASE_HPP
#define DATABASE_HPP

#include <BinaryFormat.hpp>

class Header {
   private:
    std::string _projectName;
    std::string _version;
   public:
    Header() {};
    Header(std::string projectName, std::string version)
        : _projectName(projectName), _version(version) {}
    ~Header() {}
    std::string getProjectName() const { return _projectName;};
    std::string getVersion() const { return _version;};

    void serialize(std::ostream &out) const;
    static Header deserialize(std::istream &in, uint32_t projectNameSize, uint32_t versionSize);
};

struct FileHeader {
    uint32_t projectNameSize;
    uint32_t versionSize;

    uint64_t instructionOffset;
    uint64_t instructionSize;
    uint64_t symbolOffset;
    uint64_t symbolSize;

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
