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
include lib/CMakeFiles/ARIA_MODULE.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include lib/CMakeFiles/ARIA_MODULE.dir/compiler_depend.make

# Include the progress variables for this target.
include lib/CMakeFiles/ARIA_MODULE.dir/progress.make

# Include the compile flags for this target's objects.
include lib/CMakeFiles/ARIA_MODULE.dir/flags.make

lib/CMakeFiles/ARIA_MODULE.dir/lea.c.o: lib/CMakeFiles/ARIA_MODULE.dir/flags.make
lib/CMakeFiles/ARIA_MODULE.dir/lea.c.o: ../lib/lea.c
lib/CMakeFiles/ARIA_MODULE.dir/lea.c.o: lib/CMakeFiles/ARIA_MODULE.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object lib/CMakeFiles/ARIA_MODULE.dir/lea.c.o"
	cd /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/build/lib && /Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT lib/CMakeFiles/ARIA_MODULE.dir/lea.c.o -MF CMakeFiles/ARIA_MODULE.dir/lea.c.o.d -o CMakeFiles/ARIA_MODULE.dir/lea.c.o -c /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/lib/lea.c

lib/CMakeFiles/ARIA_MODULE.dir/lea.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/ARIA_MODULE.dir/lea.c.i"
	cd /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/build/lib && /Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/lib/lea.c > CMakeFiles/ARIA_MODULE.dir/lea.c.i

lib/CMakeFiles/ARIA_MODULE.dir/lea.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/ARIA_MODULE.dir/lea.c.s"
	cd /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/build/lib && /Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/lib/lea.c -o CMakeFiles/ARIA_MODULE.dir/lea.c.s

lib/CMakeFiles/ARIA_MODULE.dir/aria.c.o: lib/CMakeFiles/ARIA_MODULE.dir/flags.make
lib/CMakeFiles/ARIA_MODULE.dir/aria.c.o: ../lib/aria.c
lib/CMakeFiles/ARIA_MODULE.dir/aria.c.o: lib/CMakeFiles/ARIA_MODULE.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object lib/CMakeFiles/ARIA_MODULE.dir/aria.c.o"
	cd /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/build/lib && /Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT lib/CMakeFiles/ARIA_MODULE.dir/aria.c.o -MF CMakeFiles/ARIA_MODULE.dir/aria.c.o.d -o CMakeFiles/ARIA_MODULE.dir/aria.c.o -c /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/lib/aria.c

lib/CMakeFiles/ARIA_MODULE.dir/aria.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/ARIA_MODULE.dir/aria.c.i"
	cd /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/build/lib && /Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/lib/aria.c > CMakeFiles/ARIA_MODULE.dir/aria.c.i

lib/CMakeFiles/ARIA_MODULE.dir/aria.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/ARIA_MODULE.dir/aria.c.s"
	cd /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/build/lib && /Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/lib/aria.c -o CMakeFiles/ARIA_MODULE.dir/aria.c.s

lib/CMakeFiles/ARIA_MODULE.dir/block.c.o: lib/CMakeFiles/ARIA_MODULE.dir/flags.make
lib/CMakeFiles/ARIA_MODULE.dir/block.c.o: ../lib/block.c
lib/CMakeFiles/ARIA_MODULE.dir/block.c.o: lib/CMakeFiles/ARIA_MODULE.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object lib/CMakeFiles/ARIA_MODULE.dir/block.c.o"
	cd /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/build/lib && /Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT lib/CMakeFiles/ARIA_MODULE.dir/block.c.o -MF CMakeFiles/ARIA_MODULE.dir/block.c.o.d -o CMakeFiles/ARIA_MODULE.dir/block.c.o -c /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/lib/block.c

lib/CMakeFiles/ARIA_MODULE.dir/block.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/ARIA_MODULE.dir/block.c.i"
	cd /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/build/lib && /Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/lib/block.c > CMakeFiles/ARIA_MODULE.dir/block.c.i

lib/CMakeFiles/ARIA_MODULE.dir/block.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/ARIA_MODULE.dir/block.c.s"
	cd /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/build/lib && /Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/lib/block.c -o CMakeFiles/ARIA_MODULE.dir/block.c.s

# Object files for target ARIA_MODULE
ARIA_MODULE_OBJECTS = \
"CMakeFiles/ARIA_MODULE.dir/lea.c.o" \
"CMakeFiles/ARIA_MODULE.dir/aria.c.o" \
"CMakeFiles/ARIA_MODULE.dir/block.c.o"

# External object files for target ARIA_MODULE
ARIA_MODULE_EXTERNAL_OBJECTS =

lib/libARIA_MODULE.dylib: lib/CMakeFiles/ARIA_MODULE.dir/lea.c.o
lib/libARIA_MODULE.dylib: lib/CMakeFiles/ARIA_MODULE.dir/aria.c.o
lib/libARIA_MODULE.dylib: lib/CMakeFiles/ARIA_MODULE.dir/block.c.o
lib/libARIA_MODULE.dylib: lib/CMakeFiles/ARIA_MODULE.dir/build.make
lib/libARIA_MODULE.dylib: lib/CMakeFiles/ARIA_MODULE.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Linking C shared library libARIA_MODULE.dylib"
	cd /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/build/lib && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/ARIA_MODULE.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
lib/CMakeFiles/ARIA_MODULE.dir/build: lib/libARIA_MODULE.dylib
.PHONY : lib/CMakeFiles/ARIA_MODULE.dir/build

lib/CMakeFiles/ARIA_MODULE.dir/clean:
	cd /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/build/lib && $(CMAKE_COMMAND) -P CMakeFiles/ARIA_MODULE.dir/cmake_clean.cmake
.PHONY : lib/CMakeFiles/ARIA_MODULE.dir/clean

lib/CMakeFiles/ARIA_MODULE.dir/depend:
	cd /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/lib /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/build /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/build/lib /Users/kimkyeongjoon/Desktop/Practice/mygit/Crypto_C/Crypto_Mode/build/lib/CMakeFiles/ARIA_MODULE.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : lib/CMakeFiles/ARIA_MODULE.dir/depend

