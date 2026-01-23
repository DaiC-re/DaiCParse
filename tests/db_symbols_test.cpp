#define CATCH_CONFIG_MAIN

#include <catch2/catch_test_macros.hpp>

#include "database/Symbol.hpp"

TEST_CASE("Symbol: Constructor with parameters", "[Symbol]") {
        const uint64_t address = 0x1000;
        const std::string name = "test_symbol";
        const DataType type = DataType::data;

        Symbol symbol(address, name, type);

        REQUIRE(symbol.getAddress() == address);
        REQUIRE(symbol.getName() == name);
        REQUIRE(symbol.getTypeString() == "Data");
}

TEST_CASE("Symbol: Constructor with different DataTypes", "[Symbol]") {
        SECTION("Function type") {
            Symbol symbol(0x2000, "func_symbol", DataType::function);
            REQUIRE(symbol.getTypeString() == "Function");
        }

        SECTION("Variable type") {
            Symbol symbol(0x3000, "var_symbol", DataType::variable);
            REQUIRE(symbol.getTypeString() == "Variable");
        }

        SECTION("Call type") {
            Symbol symbol(0x4000, "call_symbol", DataType::call);
            REQUIRE(symbol.getTypeString() == "Call");
        }

        SECTION("Data type") {
            Symbol symbol(0x5000, "data_symbol", DataType::data);
            REQUIRE(symbol.getTypeString() == "Data");
        }
}

TEST_CASE("Symbol: getTypeString method", "[Symbol]") {
        Symbol symbol(0x1000, "test", DataType::function);
        REQUIRE(symbol.getTypeString() == "Function");

        Symbol symbol2(0x2000, "test2", DataType::variable);
        REQUIRE(symbol2.getTypeString() == "Variable");
}

TEST_CASE("Function: Constructor with parameters", "[Function]") {
        const uint64_t start_addr = 0x1000;
        const uint64_t end_addr = 0x2000;
        const std::string name = "main";
        const std::vector<std::string> parameters = {"argc", "argv"};
        const std::string return_type = "int";

        Function function(start_addr, end_addr, name, parameters, return_type);

        REQUIRE(function.getStartAddress() == start_addr);
        REQUIRE(function.getEndAddress() == end_addr);
        REQUIRE(function.getName() == name);
        REQUIRE(function.getReturnType() == return_type);
        REQUIRE(function.getParameters() == parameters);
}

TEST_CASE("Function: Address validation", "[Function]") {
        Function function(0x1000, 0x2000, "func", {}, "void");

        REQUIRE(function.getStartAddress() == 0x1000);
        REQUIRE(function.getEndAddress() == 0x2000);
        REQUIRE(function.getEndAddress() > function.getStartAddress());
}

TEST_CASE("Function: Function name handling", "[Function]") {
        SECTION("Simple name") {
            Function function(0x1000, 0x2000, "simple_func", {}, "void");
            REQUIRE(function.getName() == "simple_func");
        }

        SECTION("Empty name") {
            Function function(0x1000, 0x2000, "", {}, "void");
            REQUIRE(function.getName() == "");
        }

        SECTION("Name with special characters") {
            Function function(0x1000, 0x2000, "_Z3addii", {}, "int");
            REQUIRE(function.getName() == "_Z3addii");
        }
}

TEST_CASE("Function: Parameters handling", "[Function]") {
        SECTION("No parameters") {
            Function function(0x1000, 0x2000, "func", {}, "void");
            REQUIRE(function.getParameters().empty());
        }

        SECTION("Single parameter") {
            std::vector<std::string> params = {"int"};
            Function function(0x1000, 0x2000, "func", params, "void");
            REQUIRE(function.getParameters().size() == 1);
            REQUIRE(function.getParameters()[0] == "int");
        }

        SECTION("Multiple parameters") {
            std::vector<std::string> params = {"int", "const char*", "double"};
            Function function(0x1000, 0x2000, "func", params, "void");
            REQUIRE(function.getParameters().size() == 3);
            REQUIRE(function.getParameters()[0] == "int");
            REQUIRE(function.getParameters()[1] == "const char*");
            REQUIRE(function.getParameters()[2] == "double");
        }
}

TEST_CASE("Function: Return type handling", "[Function]") {
        SECTION("void return type") {
            Function function(0x1000, 0x2000, "func", {}, "void");
            REQUIRE(function.getReturnType() == "void");
        }

        SECTION("Primitive return type") {
            Function function(0x1000, 0x2000, "func", {}, "int");
            REQUIRE(function.getReturnType() == "int");
        }

        SECTION("Pointer return type") {
            Function function(0x1000, 0x2000, "func", {}, "void*");
            REQUIRE(function.getReturnType() == "void*");
        }

        SECTION("Complex return type") {
            Function function(0x1000, 0x2000, "func", {}, "std::vector<int>");
            REQUIRE(function.getReturnType() == "std::vector<int>");
        }
}

TEST_CASE("Function: DataType is set to function", "[Function]") {
        Function function(0x1000, 0x2000, "test_func", {}, "int");
        REQUIRE(function.getTypeString() == "Function");
}

TEST_CASE("Function: Multiple instances are independent", "[Function]") {
        Function func1(0x1000, 0x2000, "func1", {"int"}, "void");
        Function func2(0x3000, 0x4000, "func2", {"double"}, "int");

        REQUIRE(func1.getStartAddress() == 0x1000);
        REQUIRE(func2.getStartAddress() == 0x3000);
        REQUIRE(func1.getName() == "func1");
        REQUIRE(func2.getName() == "func2");
}

TEST_CASE("Function: Complex real-world function", "[Function]") {
        std::vector<std::string> params = {"std::string&", "const int*",
                                           "volatile bool"};
        Function function(0x10000, 0x12000, "processData", params,
                          "std::pair<bool, int>");

        REQUIRE(function.getStartAddress() == 0x10000);
        REQUIRE(function.getEndAddress() == 0x12000);
        REQUIRE(function.getName() == "processData");
        REQUIRE(function.getParameters().size() == 3);
        REQUIRE(function.getReturnType() == "std::pair<bool, int>");
}