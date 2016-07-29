require 'rake/testtask'
Rake::TestTask.new do |t|
  t.name = 'test'
  t.test_files = FileList['test/**/*_test.rb']
  t.verbose = true
end
require 'wwtd/tasks'
task 'default' => 'wwtd'

require 'yard'
YARD::Rake::YardocTask.new do |t|
end

require 'api_hammer/tasks'
