project('XmlSigner', 'vala', 'c', version: '1.0.0')

xmlsec_flags = run_command('pkg-config', '--cflags', 'xmlsec1', capture: true, check: true)
xmlsec_libs = run_command('pkg-config', '--libs', 'xmlsec1', capture: true, check: true)

message(xmlsec_flags.stdout().strip().split(' '))

inc_directories = ['/usr/local/Cellar/libxml2/2.13.3/include/libxml2']
include_dir = include_directories(inc_directories)
vapi_dir = meson.current_source_dir()  + '/vapi'
add_project_arguments(['--vapidir', vapi_dir], language: 'vala')
#add_project_arguments([xmlsec_flags.stdout()], language: 'c')
add_project_arguments(xmlsec_flags.stdout().strip().split(' '), language: 'c')
add_project_arguments(xmlsec_libs.stdout().strip().split(' '), language: 'c')
add_project_arguments(['--pkg', 'libxml-2.0'], language: 'vala')

sources = [
    'src/ccode/functions.c',
    'src/Classes/SBXmlSigner.vala',
]
dependencies = [
    dependency('glib-2.0'),
    dependency('gobject-2.0'),
    dependency('gee-0.8'),
    #dependency('libxml-2.0', method: 'pkg-config'),
    dependency('gio-2.0'),
    dependency('libgcrypt'),
    dependency('gnutls'),
    #dependency('xmlsec1', 'pkg-config'),
    meson.get_compiler('c').find_library('libxml2', dirs: '/usr/local/Cellar/libxml2/2.13.3/lib'),
    meson.get_compiler('c').find_library('xmlsec1'),
    meson.get_compiler('c').find_library('xmlsec1-openssl'),
    meson.get_compiler('c').find_library('crypto'),
    meson.get_compiler('c').find_library('xslt'),
    meson.get_compiler('c').find_library('z'),
    meson.get_compiler('c').find_library('pthread'),
    meson.get_compiler('c').find_library('m'),
]

#add_project_arguments([xmlsec_flags.stdout()], language: 'c')

libxmlsigner = shared_library(
	'xmlsigner',
	sources,
	dependencies: dependencies,
	include_directories : include_dir,
	install: true
)
libxmlsigner_dep = declare_dependency(
	include_directories : include_dir,
	link_with : libxmlsigner
)
signer_test = executable('signer-test',
  'test/signer-test.vala',
  dependencies: [
    dependency('glib-2.0'),
    libxmlsigner_dep
  ]
)
# test('test1', signer_test)
