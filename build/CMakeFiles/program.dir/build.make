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
CMAKE_SOURCE_DIR = /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/ARIA

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/ARIA/build

# Include any dependencies generated for this target.
include CMakeFiles/program.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/program.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/program.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/program.dir/flags.make

CMakeFiles/program.dir/test/test.c.o: CMakeFiles/program.dir/flags.make
CMakeFiles/program.dir/test/test.c.o: ../test/test.c
CMakeFiles/program.dir/test/test.c.o: CMakeFiles/program.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/ARIA/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/program.dir/test/test.c.o"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/program.dir/test/test.c.o -MF CMakeFiles/program.dir/test/test.c.o.d -o CMakeFiles/program.dir/test/test.c.o -c /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/ARIA/test/test.c

CMakeFiles/program.dir/test/test.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/program.dir/test/test.c.i"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/ARIA/test/test.c > CMakeFiles/program.dir/test/test.c.i

CMakeFiles/program.dir/test/test.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/program.dir/test/test.c.s"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/ARIA/test/test.c -o CMakeFiles/program.dir/test/test.c.s

# Object files for target program
program_OBJECTS = \
"CMakeFiles/program.dir/test/test.c.o"

# External object files for target program
program_EXTERNAL_OBJECTS =

program: CMakeFiles/program.dir/test/test.c.o
program: CMakeFiles/program.dir/build.make
program: lib/libARIA_MODULE.dylib
program: CMakeFiles/program.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/ARIA/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable program"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/program.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/program.dir/build: program
.PHONY : CMakeFiles/program.dir/build

CMakeFiles/program.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/program.dir/cmake_clean.cmake
.PHONY : CMakeFiles/program.dir/clean

CMakeFiles/program.dir/depend:
	cd /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/ARIA/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/ARIA /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/ARIA /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/ARIA/build /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/ARIA/build /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/ARIA/build/CMakeFiles/program.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/program.dir/depend

