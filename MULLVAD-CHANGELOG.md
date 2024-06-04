# Changelog
All notable changes are recorded here.

### Format

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/).

Entries should have the imperative form, just like commit messages. Start each entry with words like
add, fix, increase, force etc.. Not added, fixed, increased, forced etc.

Line wrap the file at 100 chars.                                              That is over here -> |

### Categories each change fall into

* **Added**: for new features.
* **Changed**: for changes in existing functionality.
* **Deprecated**: for soon-to-be removed features.
* **Removed**: for now removed features.
* **Fixed**: for any bug fixes.
* **Security**: in case of vulnerabilities.

## [Unreleased]

## [1.1.3] - 2024-08-12
### Changed
- Remove cross-certificate requirement from `build.bat`.

### Fixed
- Fix `build.bat` for ARM64.

## [1.1.2] - 2024-08-12
### Added
- Add build config for ARM64.

## [1.1.1] - 2024-06-04
### Fixed
- Fix invalid writes to DAITA event buffer after cleanup.

## [1.1.0] - 2024-03-14
### Added
- Initial DAITA release.

## [1.0.0] - 2021-11-22
### Changed
- Permit routes leading back to the wireguard interface. This is used for implementing multihop.
