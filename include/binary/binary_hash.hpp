#include "binary.hpp"
#include <functional>

namespace std {
	template <>
	struct hash<Binary::Function> {
		size_t operator()(const Binary::Function& func) const {
			size_t h_name = std::hash<std::string>()(func.getName());
			size_t h_start = std::hash<uintptr_t>()(func.getStart());
			size_t h_end = std::hash<uintptr_t>()(func.getEnd());
			return h_name ^ (h_start << 1) ^ (h_end << 2);
		}
	};
}


struct FunctionHasher {
	size_t operator()(const std::vector<Binary::Function>& funcs) const {
		size_t hash = 0;
		for (const auto& func : funcs) {
			hash ^= std::hash<Binary::Function>()(func);
		}
		return hash;
	};
};
