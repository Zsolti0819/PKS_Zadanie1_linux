# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.20

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
CMAKE_COMMAND = /snap/clion/164/bin/cmake/linux/bin/cmake

# The command to remove a file.
RM = /snap/clion/164/bin/cmake/linux/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/zsolti/CLionProjects/PKS_Zadanie1_linux

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/zsolti/CLionProjects/PKS_Zadanie1_linux/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/PKS_Z1.dir/depend.make
# Include the progress variables for this target.
include CMakeFiles/PKS_Z1.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/PKS_Z1.dir/flags.make

CMakeFiles/PKS_Z1.dir/main.c.o: CMakeFiles/PKS_Z1.dir/flags.make
CMakeFiles/PKS_Z1.dir/main.c.o: ../main.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/zsolti/CLionProjects/PKS_Zadanie1_linux/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/PKS_Z1.dir/main.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/PKS_Z1.dir/main.c.o -c /home/zsolti/CLionProjects/PKS_Zadanie1_linux/main.c

CMakeFiles/PKS_Z1.dir/main.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/PKS_Z1.dir/main.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/zsolti/CLionProjects/PKS_Zadanie1_linux/main.c > CMakeFiles/PKS_Z1.dir/main.c.i

CMakeFiles/PKS_Z1.dir/main.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/PKS_Z1.dir/main.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/zsolti/CLionProjects/PKS_Zadanie1_linux/main.c -o CMakeFiles/PKS_Z1.dir/main.c.s

# Object files for target PKS_Z1
PKS_Z1_OBJECTS = \
"CMakeFiles/PKS_Z1.dir/main.c.o"

# External object files for target PKS_Z1
PKS_Z1_EXTERNAL_OBJECTS =

PKS_Z1: CMakeFiles/PKS_Z1.dir/main.c.o
PKS_Z1: CMakeFiles/PKS_Z1.dir/build.make
PKS_Z1: /usr/lib/x86_64-linux-gnu/libpcap.so
PKS_Z1: CMakeFiles/PKS_Z1.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/zsolti/CLionProjects/PKS_Zadanie1_linux/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable PKS_Z1"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/PKS_Z1.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/PKS_Z1.dir/build: PKS_Z1
.PHONY : CMakeFiles/PKS_Z1.dir/build

CMakeFiles/PKS_Z1.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/PKS_Z1.dir/cmake_clean.cmake
.PHONY : CMakeFiles/PKS_Z1.dir/clean

CMakeFiles/PKS_Z1.dir/depend:
	cd /home/zsolti/CLionProjects/PKS_Zadanie1_linux/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/zsolti/CLionProjects/PKS_Zadanie1_linux /home/zsolti/CLionProjects/PKS_Zadanie1_linux /home/zsolti/CLionProjects/PKS_Zadanie1_linux/cmake-build-debug /home/zsolti/CLionProjects/PKS_Zadanie1_linux/cmake-build-debug /home/zsolti/CLionProjects/PKS_Zadanie1_linux/cmake-build-debug/CMakeFiles/PKS_Z1.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/PKS_Z1.dir/depend

