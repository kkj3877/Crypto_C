# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.23

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/local/Cellar/cmake/3.23.2/bin/cmake

# The command to remove a file.
RM = /usr/local/Cellar/cmake/3.23.2/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/build

# Include any dependencies generated for this target.
include test/CMakeFiles/test_lea.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include test/CMakeFiles/test_lea.dir/compiler_depend.make

# Include the progress variables for this target.
include test/CMakeFiles/test_lea.dir/progress.make

# Include the compile flags for this target's objects.
include test/CMakeFiles/test_lea.dir/flags.make

test/CMakeFiles/test_lea.dir/test_lea.c.o: test/CMakeFiles/test_lea.dir/flags.make
test/CMakeFiles/test_lea.dir/test_lea.c.o: ../test/test_lea.c
test/CMakeFiles/test_lea.dir/test_lea.c.o: test/CMakeFiles/test_lea.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object test/CMakeFiles/test_lea.dir/test_lea.c.o"
	cd /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/build/test && /Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT test/CMakeFiles/test_lea.dir/test_lea.c.o -MF CMakeFiles/test_lea.dir/test_lea.c.o.d -o CMakeFiles/test_lea.dir/test_lea.c.o -c /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/test/test_lea.c

test/CMakeFiles/test_lea.dir/test_lea.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/test_lea.dir/test_lea.c.i"
	cd /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/build/test && /Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/test/test_lea.c > CMakeFiles/test_lea.dir/test_lea.c.i

test/CMakeFiles/test_lea.dir/test_lea.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/test_lea.dir/test_lea.c.s"
	cd /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/build/test && /Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/test/test_lea.c -o CMakeFiles/test_lea.dir/test_lea.c.s

# Object files for target test_lea
test_lea_OBJECTS = \
"CMakeFiles/test_lea.dir/test_lea.c.o"

# External object files for target test_lea
test_lea_EXTERNAL_OBJECTS =

test/test_lea: test/CMakeFiles/test_lea.dir/test_lea.c.o
test/test_lea: test/CMakeFiles/test_lea.dir/build.make
test/test_lea: lib/libCRYPTO_MODULE.dylib
test/test_lea: test/CMakeFiles/test_lea.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable test_lea"
	cd /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/build/test && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/test_lea.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
test/CMakeFiles/test_lea.dir/build: test/test_lea
.PHONY : test/CMakeFiles/test_lea.dir/build

test/CMakeFiles/test_lea.dir/clean:
	cd /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/build/test && $(CMAKE_COMMAND) -P CMakeFiles/test_lea.dir/cmake_clean.cmake
.PHONY : test/CMakeFiles/test_lea.dir/clean

test/CMakeFiles/test_lea.dir/depend:
	cd /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/test /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/build /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/build/test /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/build/test/CMakeFiles/test_lea.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : test/CMakeFiles/test_lea.dir/depend

