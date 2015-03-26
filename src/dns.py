import json
import sys
import httplib
import urllib
import os

class CloudFlare( object ):
    def __init__( self, email, token ):
        self.EMAIL = email
        self.TOKEN = token

    class APIError( Exception ):
        def __init__( self, value ):
            self.value = value
        def __str__( self ):
            return self.value

    def callAPI( self, params ):
        req = httplib.HTTPSConnection( 'www.cloudflare.com' )
        req.request( 'GET', '/api_json.html?'+params )
        response = req.getresponse()
        data = response.read()
        try:
            data = json.loads( data )
        except ValueError:
            raise self.APIError( 'JSON parse failed.' )
        if data['result'] == 'error':
            raise self.APIError( data['msg'] )
        return data


    # Stats
    def stats( self, z, interval ):
        return self.callAPI( "a=%s&email=%s&tkn=%s&z=%s&interval=%s" % ( 'stats', self.EMAIL, self.TOKEN, z, interval ) )


    # Load all zones
    def zone_load_multi( self ):
        return self.callAPI( "a=%s&email=%s&tkn=%s" % ( 'zone_load_multi', self.EMAIL, self.TOKEN ) )


    # Load all DNS records
    def rec_load_all( self, z ):
        return self.callAPI( "a=%s&email=%s&tkn=%s&z=%s" % ( 'rec_load_all', self.EMAIL, self.TOKEN, z ) )

    # Zone Check
    def zone_check( self, zones ):
        return self.callAPI( "a=%s&email=%s&tkn=%s&zs=%s" % ( 'zone_check', self.EMAIL, self.TOKEN, zones ) )


    # IP Lookup
    def ip_lkup( self, ip ):
        return self.callAPI( "a=%s&email=%s&tkn=%s&ip=%s" % ( 'ip_lkup', self.EMAIL, self.TOKEN, ip ) )


    # List all current setting values
    def zone_settings( self, z ):
        return self.callAPI( "a=%s&email=%s&tkn=%s&z=%s" % ( 'zone_settings', self.EMAIL, self.TOKEN, z ) )

    # Security Level
    def sec_lvl( self, z, v ):
        return self.callAPI( "a=%s&email=%s&tkn=%s&z=%s&v=%s" % ( 'sec_lvl', self.EMAIL, self.TOKEN, z, v ) )


    # Cache Level
    def cache_lvl( self, z, v ):
        return self.callAPI( "a=%s&email=%s&tkn=%s&z=%s&v=%s" % ( 'cache_lvl', self.EMAIL, self.TOKEN, z, v ) )


    # Development Mode
    def devmode( self, z, v ):
        return self.callAPI( "a=%s&email=%s&tkn=%s&z=%s&v=%s" % ( 'devmode', self.EMAIL, self.TOKEN, z, v ) )



    # Full Zone Purge
    def fpurge_ts( self, z, v ):
        return self.callAPI( "a=%s&email=%s&tkn=%s&z=%s&v=%s" % ( 'fpurge_ts', self.EMAIL, self.TOKEN, z, v ) )


    # Whitelist IP
    def wl( self, key ):
        return self.callAPI( "a=%s&email=%s&tkn=%s&key=%s" % ( 'wl', self.EMAIL, self.TOKEN, key ) )


    # Ban/Blacklist IP
    def ban( self, key ):
        return self.callAPI( "a=%s&email=%s&tkn=%s&key=%s" % ( 'ban', self.EMAIL, self.TOKEN, key ) )


    # Create new DNS Record
    def rec_new( self, zone, _type, content, name ):
        fmt = "a=%s&email=%s&tkn=%s&z=%s&type=%s&content=%s&name=%s&ttl=1"
        values = ('rec_new', self.EMAIL, self.TOKEN, zone, _type, content, name)
        return self.callAPI( fmt % values )


    # Delete DNS record
    def rec_delete( self, zone, id ):
        return self.callAPI( "a=%s&email=%s&tkn=%s&z=%s&id=%s" % ( 'rec_delete', self.EMAIL, self.TOKEN, zone, id ) )


    # Edit an existing record
    def rec_edit( self, z, _type, _id, name, content, service_mode=1, ttl=1 ):
        fmt = "a=%s&tkn=%s&id=%s&email=%s&z=%s&type=%s&name=%s&content=%s&ttl=%s&service_mode=%s"
        return self.callAPI( fmt % ( 'rec_edit', self.TOKEN, _id, self.EMAIL, z, _type, name, content, ttl, service_mode))


    # Toggle IPv6 support
    def ipv46( self, z, v ):
        return self.callAPI( "a=%s&email=%s&tkn=%s&z=%s&v=%s" % ( 'ipv46', self.EMAIL, self.TOKEN, z, v ) )


    # Single file purge DROP-IN
    def zone_file_purge( self, z, v ):
        return self.callAPI( "a=%s&email=%s&tkn=%s&z=%s&url=%s" % ( 'zone_file_purge', self.EMAIL, self.TOKEN, z, v ) )
    
if __name__ == "__main__":
    os.system(['clear','cls'][os.name == 'nt'])
    # If less than 3 arguments were used
    if len(sys.argv) < 4:
        if sys.argv[1] == 'actions':
            print 'You can issue the following actions'
            print ''
            print 'zones\n\tFetch all zones'
            print 'dns.domain\n\tFetch all dns records from a domain\n\tEx: dns.example.com'
            print 'dns.create.domain.type "content" "name"\n\tCreate a new DNS entry\n\tEx: dns.create.example.com.A "127.0.0.1" "localhost"'
            print 'dns.delete.domain.id\n\tRemove a DNS entry\n\tEx: dns.delete.example.com.23734516'
            print 'whitelist ip\n\tWhitelist an IP\n\tEx: whitelist 127.0.0.1'
            print 'blacklist ip\n\tBlacklist an IP\n\tEx: blacklist 127.0.0.1'
            print 'lookup ip\n\tCheck threat score for an IP\n\tEx: lookup 127.0.0.1'
        else:
            print 'Usage: dns.py email apikey action'
            print ''
            print 'Example: dns.py email@example.com f970e2767d0cfe75876ea857f92e319b zones'
            
    else:
        # Init CloudFlare
        cfapi = CloudFlare(sys.argv[1], sys.argv[2])
        
        # ZONE ACTIONS
        if sys.argv[3] == 'zones':
            print json.dumps(cfapi.zone_load_multi())
            
        # DNS ACTIONS
        if sys.argv[3].startswith('dns.'):
            ## If create action was issued
            if sys.argv[3].startswith('dns.create'):
                ### Only continue if content was provided for DNS data
                if not len(sys.argv) < 6:
                    #### Split data into core pieces
                    dns, create, domain, tld, type = sys.argv[3].split('.', 5)
                    # Assemble domain
                    domain = '%s.%s' %(domain, tld)
                    # Print json response
                    print json.dumps(cfapi.rec_new(domain, type, sys.argv[4], sys.argv[5]))
                else:
                    print 'Usage: dns.create.example.com.A "127.0.0.1" "localhost"'
                    
            ## If delete action was issued
            elif sys.argv[3].startswith('dns.delete'):
                try:
                    #### Split data into core pieces
                    dns, delete, domain, tld, id = sys.argv[3].split('.', 5)
                    # Assemble domain
                    domain = '%s.%s' %(domain, tld)
                    # Print json response
                    print json.dumps(cfapi.rec_delete(domain, id))
                except Exception as e:
                    print 'Usage: dns.delete.example.com.23734516'
                
            ## If no action was issued and a domain was entered
            else:
                #### Split domain into core pieces
                try:
                    dns, domain, tld = sys.argv[3].split('.', 3)
                    # Assemble domain
                    domain = '%s.%s' %(domain, tld)
                    if not len(sys.argv) < 5:
                        ## If readable was entered
                        if sys.argv[4] == 'readable':
                            data = cfapi.rec_load_all(domain)
                            
                            for i, value in enumerate(data['response']['recs']['objs']):
                                print '%s:%s %s:%s %s:%s %s:%s %s:%s %s:%s %s:%s %s:%s %s:%s %s:%s %s:%s %s:%s %s:%s %s:%s %s:%s %s:%s' %('display_content', data['response']['recs']['objs'][i]['display_content'],
                                'display_name', data['response']['recs']['objs'][i]['display_name'],
                                'name', data['response']['recs']['objs'][i]['name'],
                                'prio', data['response']['recs']['objs'][i]['prio'],
                                'auto_ttl', data['response']['recs']['objs'][i]['auto_ttl'],
                                'rec_hash', data['response']['recs']['objs'][i]['rec_hash'],
                                'rec_id', data['response']['recs']['objs'][i]['rec_id'],
                                'content', data['response']['recs']['objs'][i]['content'],
                                'service_mode', data['response']['recs']['objs'][i]['service_mode'],
                                'ssl_expires_on', data['response']['recs']['objs'][i]['ssl_expires_on'],
                                'ssl_id', data['response']['recs']['objs'][i]['ssl_id'],
                                'ssl_status', data['response']['recs']['objs'][i]['ssl_status'],
                                'ttl', data['response']['recs']['objs'][i]['ttl'],
                                'zone_name', data['response']['recs']['objs'][i]['zone_name'],
                                'type', data['response']['recs']['objs'][i]['type'],
                                'ttl_ceil', data['response']['recs']['objs'][i]['ttl_ceil'])
                            sys.exit()
                    
                    # Print json response
                    print json.dumps(cfapi.rec_load_all(domain))
                except Exception as e:
                    print 'Usage: dns.example.com'
        
        # WHITELIST IP
        if sys.argv[3] == 'whitelist':
            ### Only continue if content was provided for IP lookup
            if not len(sys.argv) < 5:
                # Print json response
                print json.dumps(cfapi.wl(sys.argv[4]))
            else:
                print 'Usage: whitelist 127.0.0.1'
        
        # BLACKLIST IP
        if sys.argv[3] == 'blacklist':
            ### Only continue if content was provided for IP lookup
            if not len(sys.argv) < 5:
                # Print json response
                print json.dumps(cfapi.ban(sys.argv[4]))
            else:
                print 'Usage: blacklist 127.0.0.1'
        
        # LOOKUP
        if sys.argv[3] == 'lookup':
            print 'Reported broken. Check https://github.com/TunkDesign/SimpleCloudflare to see if it has been fixed!'
            sys.exit()
            
            ### Only continue if content was provided for IP lookup
            if not len(sys.argv) < 5:
                # Print json response
                print json.dumps(cfapi.ip_lkup(sys.argv[4]))
            else:
                print 'Usage: lookup 127.0.0.1'