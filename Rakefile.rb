require 'rake/testtask'
Rake::TestTask.new do |t|
  t.name = 'test'
  t.test_files = FileList['test/**/*_test.rb']
  t.verbose = true
end

task 'default' => 'test'

require 'yard'
YARD::Rake::YardocTask.new do |t|
end

require 'api_hammer/tasks'

begin
  require 'gig'
  gig_loaded = true
rescue LoadError
end

if gig_loaded
  ignore_files = %w(
    .github/**/*
    .gitignore
    Gemfile*
    config.ru
    Rakefile.rb
    oauthenticator.gemspec
    test/**/*
  ).map { |glob| Dir.glob(glob, File::FNM_DOTMATCH) }.inject([], &:|)
  Gig.make_task(gemspec_filename: 'oauthenticator.gemspec', ignore_files: ignore_files)
end
