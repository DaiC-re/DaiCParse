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
    uint64_t functionsOffset;
    uint64_t functionsSize;
    uint64_t checkpointOffset;
    uint64_t checkpointSize;

    size_t instructionCount;

    void serialize(std::ostream &out) const;
    void deserialize(std::istream &in);
};

class Database {
   private:
    std::unique_ptr<Binary> &_binary;
    std::string _path;
   public:
    Database(std::unique_ptr<Binary> &binary): _binary(binary) {};
    Database(std::unique_ptr<Binary> &binary, const std::string &path): _binary(binary), _path(path) {};
    ~Database() {}

    std::unique_ptr<BinaryMetadata> &getMetadata() const { return _binary->metadata;};

    void createProject(const std::string &path);

    void serialize() const;
    template <typename Data>
    void serializeData(Data &datas, std::ostream &out, uint64_t &offset, uint64_t &size) const;
    void serializeUint(std::vector<uintptr_t> &datas, std::ostream &out, uint64_t &offset, uint64_t &size) const;

    static Database deserialize(const std::string &filepath, std::unique_ptr<Binary> &binary);

    template <typename Data>
    static void deserializeData(std::vector<Data> &datas, std::istream &in, uint64_t &offset, uint64_t &size);
    static void deserializeUint(std::vector<uintptr_t> &datas, std::istream &in, uint64_t &offset, uint64_t &size);
};

#endif  // DATABASE_HPP
