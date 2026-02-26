Refacto for making DaiCParse standalone:

Add tests for the whole library:

Add a dummy binary for binary_test:
- Makes the tests way less portable
- Allow us to test the whole library even IO files without ugly mock
- Respects catch2 philosophy with fixtures

Add tests for bin_section:
- No tradeoff, went well

Add end to end tests:
- No tradeoff, went well
- Will not run on the CI since it uses more ressources

Quality checks:

- Re-add clang-format and clang-tidy configs from DaiC for the DaiCParse library
- Add a CI robot which auto commits clang-format at each pull request

- Use Sonarqube and semgrep for static analysis of the project, sonarqube integrates well into IDEs and semgrep is great for checking fast if all goes well.
  Clang-tidy is too strict and has a lot of false positives so it's only useful for tips

Package distribution:
Context: Library for use in other projects
Alternatives: add_subdirectory, vcpkg, Conan, ...
At the moment we choose to use FetchContent as the default way of using DaiCParse,
adding it to vcpkg/Conan would be modern but as convenient.

Documentation:
Add documentations for users, contributers and dev,
we should make a mdbook later for having a more readable, online guide.