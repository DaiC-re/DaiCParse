# DaiCParse Contributor Guide

## Introduction

### What is DaiCParse?

DaiC Parse is an library for easely parsing binaries.
It leverages the LIEF library but provides more high level and platform independents results.
It also integrates the Capstone library for disassembling binaries.

### What is this guide?

This guide is for anyone who wants to contribute to DaiCParse. It's a work in progress, and will be updated regularly.

### How can I contribute?

There are many ways to contribute to DaiCParse. You can:

- [Report a bug](https://github.com/DaiC-re/DaiCParse/issues/new)
- Submit a PR

## Working with DaiCParse

### Development Requirements

Before anything else, make sure you have the following installed:

- CMake 3.25.0+
- gcc/clang/msvc which supports c++23

### General Workflow

Since this is a library and not an application, the workflow is a bit different from a typical application.
The main focus is on writing tests and making sure they pass.

You can use the provided Dockerfile to set up a development environment with all the necessary dependencies. This is the recommended way to develop for DaiCParse, as it ensures that you have a consistent environment across different machines.

Tests are located in the `tests` directory, and are built using CMake. You can run them using CTest or your preferred test runner.

You can use provided documentation to understand how the library works and how to use it. If you have any questions, feel free to ask in the [GitHub Discussions](