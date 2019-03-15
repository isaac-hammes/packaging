require 'uri'
require 'open-uri'

module Pkg

  # The Artifactory class
  # This class provides automation to access the artifactory repos maintained
  # by the Release Engineering team at Puppet. It has the ability to both push
  # artifacts to the repos, and to retrieve them back from the repos.
  class ManageArtifactory

    DEFAULT_REPO_TYPE = 'generic'
    DEFAULT_REPO_BASE = 'development'

    # @param project [String] The name of the project this package is for
    # @param project_version [String] The version of the project we want the
    #   package for. This can be one of three things:
    #     1) the final tag of the project the packages  were built from
    #     2) the long git sha the project the packages were built from
    #     3) the EZBake generated development sha where the packages live
    # @option :artifactory_uri [String] the uri for the artifactory server.
    #   This currently defaults to 'https://artifactory.delivery.puppetlabs.net/artifactory'
    # @option :repo_base [String] The base of all repos, set for consistency.
    #   This currently defaults to 'development'
    def initialize(project, project_version, opts = {})
      require 'artifactory'

      @artifactory_uri = opts[:artifactory_uri] || 'https://artifactory.delivery.puppetlabs.net/artifactory'
      @repo_base = opts[:repo_base] || DEFAULT_REPO_BASE

      @project = project
      @project_version = project_version

      Artifactory.endpoint = @artifactory_uri
    end

    # @param platform_tag [String] The platform tag string for the repo we need
    #   information on. If generic information is needed, pass in `generic`
    # @return [Array] An array containing three items, first being the main repo
    #   name for the platform_tag, the second being the subdirectories of the
    #   repo leading to the artifact we want to install, and the third being the
    #   alternate subdirectories for a given repo. This last option is only
    #   currently used for debian platforms, where the path to the repo
    #   specified in the list file is different than the full path to the repo.
    def location_for(platform_tag)
      toplevel_repo = DEFAULT_REPO_TYPE
      repo_subdirectories = File.join(@repo_base, @project, @project_version)
      alternate_subdirectories = repo_subdirectories

      unless platform_tag == DEFAULT_REPO_TYPE
        format = Pkg::Platforms.package_format_for_tag(platform_tag)
        platform, version, architecture = Pkg::Platforms.parse_platform_tag(platform_tag)
      end

      case format
      when 'rpm'
        toplevel_repo = 'rpm'
        repo_subdirectories = File.join(repo_subdirectories, "#{platform}-#{version}-#{architecture}")
        alternate_subdirectories = repo_subdirectories
      when 'deb'
        toplevel_repo = 'debian__local'
        repo_subdirectories = File.join(repo_subdirectories, "#{platform}-#{version}")
        alternate_subdirectories = File.join('pool', repo_subdirectories)
      when 'swix', 'dmg', 'svr4', 'ips'
        repo_subdirectories = File.join(repo_subdirectories, "#{platform}-#{version}-#{architecture}")
        alternate_subdirectories = repo_subdirectories
      when 'msi'
        repo_subdirectories = File.join(repo_subdirectories, "#{platform}-#{architecture}")
        alternate_subdirectories = repo_subdirectories
      end

      [toplevel_repo, repo_subdirectories, alternate_subdirectories]
    end

    # @param platform_tag [String] The platform tag specific to the information
    #   we need. If only the generic information is needed, pass in `generic`
    # @return [Hash] Returns a hash of data specific to this platform tag
    def platform_specific_data(platform_tag)
      unless platform_tag == DEFAULT_REPO_TYPE
        platform, version, architecture = Pkg::Platforms.parse_platform_tag(platform_tag)
        package_format = Pkg::Platforms.package_format_for_tag(platform_tag)
        if package_format == 'deb'
          codename = Pkg::Platforms.codename_for_platform_version(platform, version)
        end
      end

      repo_name, repo_subdirectories, alternate_subdirectories = location_for(platform_tag)
      full_artifactory_path = File.join(repo_name, alternate_subdirectories)

      {
        platform: platform,
        platform_version: version,
        architecture: architecture,
        codename: codename,
        package_format: package_format,
        repo_name: repo_name,
        repo_subdirectories: repo_subdirectories,
        alternate_subdirectories: alternate_subdirectories,
        full_artifactory_path: full_artifactory_path
      }
    end

    # @param platform_tag [String] The platform to generate the list contents
    #   for
    # @return [String] The contents of the debian list file to enable the
    #   debian artifactory repos for the specified project and version
    def deb_list_contents(platform_tag)
      data = platform_specific_data(platform_tag)
      if data[:package_format] == 'deb'
        return "deb #{@artifactory_uri}/#{data[:repo_name]} #{data[:codename]} #{data[:repo_subdirectories]}"
      end
      raise "The platform '#{platform_tag}' is not an apt-based system."
    end

    # @param platform_tag [String] The platform to generate the repo file
    #   contents for
    # @return [String] The contents of the rpm repo file to enable the rpm
    #   artifactory repo for the specified project and version
    def rpm_repo_contents(platform_tag)
      data = platform_specific_data(platform_tag)
      if data[:package_format] == 'rpm'
        return <<-DOC
  [Artifactory #{@project} #{@project_version} for #{platform_tag}]
  name=Artifactory Repository for #{@project} #{@project_version} for #{platform_tag}
  baseurl=#{@artifactory_uri}/#{data[:repo_name]}/#{data[:repo_subdirectories]}
  enabled=1
  gpgcheck=0
  #Optional - if you have GPG signing keys installed, use the below flags to verify the repository metadata signature:
  #gpgkey=#{@artifactory_uri}/#{data[:repo_name]}/#{data[:repo_subdirectories]}/repomd.xml.key
  #repo_gpgcheck=1
        DOC
      end
      raise "The platform '#{platform_tag}' is not a yum-based system"
    end

    # Verify the correct environment variables are set in order to process
    # authorization to access the artifactory repos
    def check_authorization
      unless (ENV['ARTIFACTORY_USERNAME'] && ENV['ARTIFACTORY_PASSWORD']) || ENV['ARTIFACTORY_API_KEY']
        raise <<-DOC
  Unable to determine credentials for Artifactory. Please set one of the
  following environment variables:

  For basic authentication, please set:
  ARTIFACTORY_USERNAME
  ARTIFACTORY_PASSWORD

  If you would like to use the API key, ensure ARTIFACTORY_USERNAME and
  ARTIFACTORY_PASSWORD are not set, as these take precedence. Instead, please
  set:
  ARTIFACTORY_API_KEY

  You can also set the path to a pem file with your custom certificates with:
  ARTIFACTORY_SSL_PEM_FILE
        DOC
      end
    end

    # @param platform_tag [String] The platform tag to generate deploy
    #   properties for
    # @return [String] Any required extra bits that we need for the curl
    #   command used to deploy packages to artifactory
    #
    #   These are a few examples from chef/artifactory-client. These could
    #   potentially be very powerful, but we should decide how to use them.
    #     status: 'DEV',
    #     rating: 5,
    #     branch: 'master'
    #
    #   Currently we are including everything that would be included in the yaml
    #   file that is generated at package build time.
    def deploy_properties(platform_tag)
      data = platform_specific_data(platform_tag)

      # TODO This method should be returning the entire contents of the yaml
      # file in hash form to include as metadata for these artifacts. In this
      # current iteration, the hash isn't formatted properly and the attempt to
      # deploy to Artifactory bails out. I'm leaving this in so that we at least
      # have multiple places to remind us that it needs to happen.
      #properties_hash = Pkg::Config.config_to_hash
      properties_hash = {}
      if data[:package_format] == 'deb'
        properties_hash.merge!({
          'deb.distribution' => data[:codename],
          'deb.component' => data[:repo_subdirectories],
          'deb.architecture' => data[:architecture],
        })
      end
      properties_hash
    end

    # @param package [String] The full relative path to the package to be
    #   shipped, relative from the current working directory
    def deploy_package(package)
      platform_tag = Pkg::Paths.tag_from_artifact_path(package) || DEFAULT_REPO_TYPE
      data = platform_specific_data(platform_tag)

      check_authorization
      artifact = Artifactory::Resource::Artifact.new(local_path: package)
      artifact.upload(
        data[:repo_name],
        File.join(data[:alternate_subdirectories], File.basename(package)),
        deploy_properties(platform_tag)
      )
    rescue
      raise "Attempt to upload '#{package}' to #{File.join(@artifactory_uri, data[:full_artifactory_path])} failed"
    end

    # @param pkg [String] The package to download YAML for
    #   i.e. 'puppet-agent' or 'puppetdb'
    # @param ref [String] The git ref (sha or tag) we want the YAML for
    #
    # @return [String] The contents of the YAML file
    def retrieve_yaml_data(pkg, ref)
      yaml_url = "#{@artifactory_uri}/#{DEFAULT_REPO_TYPE}/#{DEFAULT_REPO_BASE}/#{pkg}/#{ref}/#{ref}.yaml"
      open(yaml_url) { |f| f.read }
    rescue
      raise "Failed to load YAML data for #{pkg} at #{ref} from #{yaml_url}!"
    end

    # @param platform_data [Hash] The has of the platform data that needs to be
    #   parsed
    # @param platform_tag [String] The tag that the data we want belongs to
    # @return [String] The name of the package for the given project,
    #   project_version, and platform_tag
    def package_name(platform_data, platform_tag)
      return File.basename(platform_data[platform_tag][:artifact])
    rescue
      fail_message = <<-DOC
  Package name could not be found from loaded yaml data. Either this package
  does not exist, or '#{@platform_tag}' is not present in this dataset.

  The following are available platform tags for '#{@project}' '#{@project_version}':
    #{platform_data.keys.sort}
      DOC
      raise fail_message
    end

    # Promotes a build based on build SHA or tag
    # Depending on if it's an RPM or Deb package promote accordingly
    # 'promote' by copying the package(s) to the enterprise directory on artifactory
    #
    # @param pkg [String] the package name ex. puppet-agent
    # @param ref [String] tag or SHA of package(s) to be promoted
    # @param platform_tag [String] the platform tag of the artifact
    #   ex. el-7-x86_64, ubuntu-18.04-amd64
    # @param repositories [Array(String)] the repositories to promote
    #   the artifact to. Will prepend 'rpm_' or 'debian_' to the repositories
    #   depending on package type
    def promote_package(pkg, ref, platform_tag, repositories)
      # load package metadata
      yaml_content = retrieve_yaml_data(pkg, ref)
      yaml_data = YAML::load(yaml_content)

      # get the artifact name
      artifact_name = package_name(yaml_data[:platform_data], platform_tag)
      artifact_to_promote = Artifactory::Resource::Artifact.search(name: artifact_name, :artifactory_uri => @artifactory_uri)

      if artifact_to_promote.empty?
        raise "Error: could not find PKG=#{pkg} at REF=#{git_ref} for #{platform_tag}"
      end

      # This makes an assumption that we're using some consistent repo names
      # but need to either prepend 'rpm_' or 'debian_' based on package type
      if File.extname(artifact_name) == '.rpm'
        promotion_paths = Array(repositories).compact.map { |repo| "rpm_#{repo}/#{platform_tag}/#{artifact_name}" }
      else
        promotion_paths = Array(repositories).compact.map { |repo| "debian_#{repo}/#{platform_tag}/#{artifact_name}" }
      end

      begin
        promotion_paths.each do |path|
          puts "promoting #{artifact_name} to #{path}"
          artifact_to_promote[0].copy(path)
        end
      rescue
        puts "Skipping promotion of #{artifact_name}; it has already been promoted"
      end
    end

    private :check_authorization
  end
end
