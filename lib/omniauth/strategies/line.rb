require 'jwt'
require 'omniauth-oauth2'
require 'json'

module OmniAuth
  module Strategies
    class Line < OmniAuth::Strategies::OAuth2
      option :name, 'line'
      option :scope, 'profile openid email'

      option :token_params, {
        grant_type: 'authorization_code'
      }

      option :client_options, {
        site: 'https://access.line.me',
        authorize_url: '/oauth2/v2.1/authorize',
        token_url: '/oauth2/v2.1/token'
      }

      option :authorize_options, [:scope, :bot_prompt]

      def authorize_params
        super.tap do |params|
          %w[bot_prompt].each do |v|
            if request.params[v]
              params[v.to_sym] = request.params[v]
            end
          end
        end
      end

      # host changed
      def callback_phase
        options[:client_options][:site] = 'https://api.line.me'
        super
      end

      uid { raw_info['userId'] }

      info do
        {
          name:        raw_info['displayName'],
          image:       raw_info['pictureUrl'],
          description: raw_info['statusMessage'],
          email:       id_info['email']
        }
      end

      extra do
        hash = {}
        hash[:raw_info] = raw_info
        hash[:id_info] = id_info
        prune! hash
      end

      # Require: Access token with PROFILE permission issued.
      def raw_info
        @raw_info ||= JSON.load(access_token.get('v2/profile').body)
      rescue ::Errno::ETIMEDOUT
        raise ::Timeout::Error
      end

      def id_info
        @id_info ||= ::JWT.decode(access_token.params['id_token'], nil, false, { algorithm: 'HS256' }).first
      rescue ::Errno::ETIMEDOUT
        raise ::Timeout::Error
      end

      def build_access_token
        verifier = request.params["code"]
        get_token_params = {:redirect_uri => callback_url}.merge(token_params.to_hash(:symbolize_keys => true))
        result = client.auth_code.get_token(verifier, get_token_params, deep_symbolize(options.auth_token_params))
        return result
      end

      def callback_url
        full_host + script_name + callback_path
      end

      private

      def prune!(hash)
        hash.delete_if do |_, v|
          prune!(v) if v.is_a?(Hash)
          v.nil? || (v.respond_to?(:empty?) && v.empty?)
        end
      end
    end
  end
end
