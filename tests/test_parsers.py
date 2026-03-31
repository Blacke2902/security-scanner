"""Unit tests for dependency file parsers."""

from repo_security_scanner.models import Ecosystem
from repo_security_scanner.parsers.python import (
    RequirementsTxtParser, PyprojectTomlParser, PipfileLockParser, PoetryLockParser,
)
from repo_security_scanner.parsers.node import PackageJsonParser, PackageLockJsonParser, YarnLockParser, PnpmLockParser
from repo_security_scanner.parsers.java import PomXmlParser, BuildGradleParser
from repo_security_scanner.parsers.go import GoModParser
from repo_security_scanner.parsers.ruby import GemfileParser, GemfileLockParser
from repo_security_scanner.parsers.rust import CargoTomlParser, CargoLockParser
from repo_security_scanner.parsers.php import ComposerJsonParser, ComposerLockParser


class TestRequirementsTxt:
    def test_basic(self):
        content = "requests==2.31.0\nflask>=2.0.0\nnumpy~=1.24.0\n"
        deps = RequirementsTxtParser().parse(content, "requirements.txt")
        assert len(deps) == 3
        assert deps[0].name == "requests"
        assert deps[0].version == "==2.31.0"
        assert deps[0].ecosystem == Ecosystem.PYPI

    def test_comments_and_blanks(self):
        content = "# comment\nrequests==1.0\n\n-r other.txt\nflask==2.0\n"
        deps = RequirementsTxtParser().parse(content, "requirements.txt")
        assert len(deps) == 2

    def test_extras(self):
        content = "requests[security]==2.31.0\n"
        deps = RequirementsTxtParser().parse(content, "requirements.txt")
        assert deps[0].name == "requests"


class TestPyprojectToml:
    def test_project_deps(self):
        content = '''
[project]
dependencies = [
    "requests>=2.31.0",
    "rich>=13.0",
]
'''
        deps = PyprojectTomlParser().parse(content, "pyproject.toml")
        assert len(deps) == 2
        assert deps[0].name == "requests"

    def test_poetry_deps(self):
        content = '''
[tool.poetry.dependencies]
python = "^3.10"
requests = "^2.31.0"
flask = {version = "^2.0", optional = true}
'''
        deps = PyprojectTomlParser().parse(content, "pyproject.toml")
        assert len(deps) == 2
        names = {d.name for d in deps}
        assert "requests" in names
        assert "flask" in names
        assert "python" not in names


class TestPipfileLock:
    def test_basic(self):
        content = '{"default": {"requests": {"version": "==2.31.0"}}, "develop": {"pytest": {"version": "==7.4.0"}}}'
        deps = PipfileLockParser().parse(content, "Pipfile.lock")
        assert len(deps) == 2


class TestPoetryLock:
    def test_basic(self):
        content = '''
[[package]]
name = "requests"
version = "2.31.0"

[[package]]
name = "flask"
version = "2.3.2"
'''
        deps = PoetryLockParser().parse(content, "poetry.lock")
        assert len(deps) == 2
        assert deps[0].name == "requests"
        assert deps[0].version == "2.31.0"


class TestPackageJson:
    def test_basic(self):
        content = '{"dependencies": {"express": "^4.18.0"}, "devDependencies": {"jest": "^29.0.0"}}'
        deps = PackageJsonParser().parse(content, "package.json")
        assert len(deps) == 2
        assert deps[0].ecosystem == Ecosystem.NPM


class TestPackageLockJson:
    def test_v2(self):
        content = '{"packages": {"": {"name": "root"}, "node_modules/express": {"version": "4.18.2"}}}'
        deps = PackageLockJsonParser().parse(content, "package-lock.json")
        assert len(deps) == 1
        assert deps[0].name == "express"
        assert deps[0].version == "4.18.2"


class TestYarnLock:
    def test_basic(self):
        content = '''"express@^4.18.0":
  version "4.18.2"

"lodash@^4.17.0":
  version "4.17.21"
'''
        deps = YarnLockParser().parse(content, "yarn.lock")
        assert len(deps) == 2


class TestPomXml:
    def test_basic(self):
        content = '''<?xml version="1.0"?>
<project>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>5.3.20</version>
    </dependency>
  </dependencies>
</project>'''
        deps = PomXmlParser().parse(content, "pom.xml")
        assert len(deps) == 1
        assert deps[0].name == "org.springframework:spring-core"
        assert deps[0].version == "5.3.20"


class TestBuildGradle:
    def test_basic(self):
        content = '''dependencies {
    implementation 'org.springframework:spring-core:5.3.20'
    testImplementation "junit:junit:4.13.2"
}'''
        deps = BuildGradleParser().parse(content, "build.gradle")
        assert len(deps) == 2


class TestGoMod:
    def test_basic(self):
        content = '''module github.com/example/project

go 1.21

require (
\tgithub.com/gin-gonic/gin v1.9.1
\tgithub.com/stretchr/testify v1.8.4 // indirect
)

require github.com/pkg/errors v0.9.1
'''
        deps = GoModParser().parse(content, "go.mod")
        assert len(deps) == 3
        assert deps[0].name == "github.com/gin-gonic/gin"


class TestGemfile:
    def test_basic(self):
        content = '''source "https://rubygems.org"
gem 'rails', '~> 7.0'
gem "puma", ">= 5.0"
gem 'bootsnap'
'''
        deps = GemfileParser().parse(content, "Gemfile")
        assert len(deps) == 3
        assert deps[2].version == "*"


class TestGemfileLock:
    def test_basic(self):
        content = '''GEM
  remote: https://rubygems.org/
  specs:
    actioncable (7.0.5)
    rails (7.0.5)
      actioncable (= 7.0.5)

PLATFORMS
  ruby
'''
        deps = GemfileLockParser().parse(content, "Gemfile.lock")
        assert len(deps) == 2
        assert deps[0].name == "actioncable"


class TestCargoToml:
    def test_basic(self):
        content = '''[dependencies]
serde = "1.0"
tokio = { version = "1.28", features = ["full"] }

[dev-dependencies]
criterion = "0.5"
'''
        deps = CargoTomlParser().parse(content, "Cargo.toml")
        assert len(deps) == 3


class TestCargoLock:
    def test_basic(self):
        content = '''[[package]]
name = "serde"
version = "1.0.163"

[[package]]
name = "tokio"
version = "1.28.2"
'''
        deps = CargoLockParser().parse(content, "Cargo.lock")
        assert len(deps) == 2


class TestComposerJson:
    def test_basic(self):
        content = '{"require": {"php": "^8.1", "laravel/framework": "^10.0", "ext-json": "*"}, "require-dev": {"phpunit/phpunit": "^10.0"}}'
        deps = ComposerJsonParser().parse(content, "composer.json")
        assert len(deps) == 2  # php and ext-json skipped
        names = {d.name for d in deps}
        assert "laravel/framework" in names
        assert "phpunit/phpunit" in names


class TestComposerLock:
    def test_basic(self):
        content = '{"packages": [{"name": "laravel/framework", "version": "v10.0.0"}], "packages-dev": [{"name": "phpunit/phpunit", "version": "10.1.0"}]}'
        deps = ComposerLockParser().parse(content, "composer.lock")
        assert len(deps) == 2


class TestPnpmLock:
    def test_v6_format(self):
        content = '''lockfileVersion: '6.0'

packages:

  /express@4.18.2:
    resolution: {integrity: sha512-xxx}
    dependencies:
      accepts: 1.3.8

  /@babel/core@7.23.0:
    resolution: {integrity: sha512-yyy}
'''
        deps = PnpmLockParser().parse(content, "pnpm-lock.yaml")
        assert len(deps) == 2
        names = {d.name for d in deps}
        assert "express" in names
        assert "@babel/core" in names
        assert deps[0].ecosystem == Ecosystem.NPM

    def test_v9_format(self):
        content = """lockfileVersion: '9.0'

packages:
  'express@4.21.0':
    resolution: {integrity: sha512-xxx}
  '@types/node@20.10.0':
    resolution: {integrity: sha512-yyy}
"""
        deps = PnpmLockParser().parse(content, "pnpm-lock.yaml")
        assert len(deps) == 2
        names = {d.name for d in deps}
        assert "express" in names
        assert "@types/node" in names
