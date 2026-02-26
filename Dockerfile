# Use official Ubuntu image as base
FROM ubuntu:latest

# Set environment variables to avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    software-properties-common \
    build-essential \
    cmake \
    git \
    python3 \
    python3-pip \
    ninja-build \
    clang-format \
    cppcheck

RUN add-apt-repository universe

# Install Python dependencies
RUN apt-get install -y python3-pybind11

RUN rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /workspace

# Copy the project files
COPY . .

# Create build directory and configure
RUN mkdir -p build && cd build && \
   cmake .. -DBUILD_TESTING=TRUE -DCMAKE_BUILD_TYPE=Release && \
   cmake --build . --config Release --target install

# Default command to run when container starts
CMD ["bash"]