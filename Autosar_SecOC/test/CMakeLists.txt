cmake_minimum_required(VERSION 3.20)

set(This SecOCTests)

file(GLOB_RECURSE Sources CONFIGURE_DEPENDS "*.cpp")

# MCAL Pi4 driver functions (Dio_*, Mcu_*, Gpt_*, Wdg_*) only exist when
# building with MCAL_TARGET=PI4. McalTests.cpp references them directly, so
# when the parent configured a SIM build those symbols are absent and the
# test fails to link. Skip that test binary in SIM mode.
if(NOT MCAL_TARGET STREQUAL "PI4")
    list(FILTER Sources EXCLUDE REGEX ".*/McalTests\\.cpp$")
endif()

foreach (_file ${Sources})

    cmake_path(GET _file STEM executable)
    add_executable(${executable} ${_file})
    target_link_libraries(${executable} PUBLIC
        gtest_main
        SecOCLib
    )

    # Output JUnit XML results for Cantata-style report generation
    add_test(
        NAME ${executable}
        COMMAND ${executable} --gtest_output=xml:${CMAKE_BINARY_DIR}/test_results/${executable}.xml
    )

    # Label scheme per TL-QA spec:
    #   LIVE_PI    -> requires real Pi-to-Pi peer (not run by default)
    #   REGRESSION -> guards Phase A-D fixes
    #   UNIT       -> everything else
    # Use: ctest -L UNIT (fast loop) | ctest -L "UNIT|REGRESSION" (CI) | ctest -L LIVE_PI (HiL only)
    if(${executable} STREQUAL "DirectRxLiveTests")
        set_tests_properties(${executable} PROPERTIES LABELS "LIVE_PI" TIMEOUT 30)
    elseif(${executable} MATCHES "Phase_[A-Z]_Regression|CrossModeRejection|FailureInjection|CsmBootstrap")
        set_tests_properties(${executable} PROPERTIES LABELS "REGRESSION" TIMEOUT 60)
    else()
        set_tests_properties(${executable} PROPERTIES LABELS "UNIT" TIMEOUT 30)
    endif()

endforeach()
