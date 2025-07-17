# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies 
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Socks Proxy for the HTTP Protocol
#
#  A simple SOCKS server that proxies a connection to relayed HTTP connections
#
# Author:
#   Dirk-jan Mollema (@_dirkjan) / Fox-IT (https://www.fox-it.com)
#
import base64

from impacket import LOG
from impacket.examples.ntlmrelayx.servers.socksserver import SocksRelay

# Besides using this base class you need to define one global variable when
# writing a plugin:
PLUGIN_CLASS = "HTTPSocksRelay"
EOL = b'\r\n'

class HTTPSocksRelay(SocksRelay):
    PLUGIN_NAME = 'HTTP Socks Plugin'
    PLUGIN_SCHEME = 'HTTP'

    def __init__(self, targetHost, targetPort, socksSocket, activeRelays):
        SocksRelay.__init__(self, targetHost, targetPort, socksSocket, activeRelays)
        self.packetSize = 8192
        self.relaySocket = None
        self.session = None

    @staticmethod
    def getProtocolPort():
        return 80

    def initConnection(self):
        pass
        
    def isConnectionAlive(self):
        """Check if the relay connection is still alive"""
        if not self.relaySocket or not self.session:
            return False
        try:
            # Try to peek at the socket without consuming data
            import socket
            self.relaySocket.settimeout(0.1)
            self.relaySocket.recv(1, socket.MSG_PEEK)
            self.relaySocket.settimeout(None)
            return True
        except (socket.timeout, socket.error, OSError):
            return True  # Assume alive if we can't determine
        except Exception:
            return False

    def skipAuthentication(self):
        # See if the user provided authentication
        try:
            data = self.socksSocket.recv(self.packetSize)
            if not data:
                LOG.debug('HTTP: No data received from client')
                return False
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            LOG.debug('HTTP: Client connection error: %s' % str(e))
            return False
        
        # Check if this is a session selection request
        try:
            request_line = data.split(EOL)[0].decode("ascii")
        except (UnicodeDecodeError, IndexError):
            LOG.debug('HTTP: Invalid request format')
            return False
            
        # Check for WebSocket upgrade requests and reject them
        headers = self.getHeaders(data)
        if headers.get('upgrade', '').lower() == 'websocket':
            LOG.debug('HTTP: WebSocket upgrade request detected - rejecting')
            response = b'HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\nWebSocket not supported'
            try:
                self.socksSocket.send(response)
            except:
                pass
            return False
            
        # Get headers from data  
        headerDict = self.getHeaders(data)
        try:
            creds = headerDict['authorization']
            if 'Basic' not in creds:
                raise KeyError()
            basicAuth = base64.b64decode(creds[6:]).decode("ascii")
            self.username = basicAuth.split(':')[0].upper()
            if '@' in self.username:
                # Workaround for clients which specify users with the full FQDN
                # such as ruler
                user, domain = self.username.split('@', 1)
                # Currently we only use the first part of the FQDN
                # this might break stuff on tools that do use an FQDN
                # where the domain NETBIOS name is not equal to the part
                # before the first .
                self.username = '%s/%s' % (domain.split('.')[0], user)

            # Check if we have a connection for the user
            if self.username in self.activeRelays:
                # Check the connection is not inUse
                if self.activeRelays[self.username]['inUse'] is True:
                    LOG.error('HTTP: Connection for %s@%s(%s) is being used at the moment!' % (
                        self.username, self.targetHost, self.targetPort))
                    return False
                else:
                    LOG.info('HTTP: Proxying client session for %s@%s(%s)' % (
                        self.username, self.targetHost, self.targetPort))
                    self.session = self.activeRelays[self.username]['protocolClient'].session
            else:
                LOG.error('HTTP: No session for %s@%s(%s) available' % (
                    self.username, self.targetHost, self.targetPort))
                return False

        except KeyError:
            # User didn't provide authentication yet, prompt for it
            LOG.debug('No authentication provided, prompting for basic authentication')
            reply = [b'HTTP/1.1 401 Unauthorized',b'WWW-Authenticate: Basic realm="ntlmrelayx - provide a DOMAIN/username"',b'Connection: close',b'',b'']
            self.socksSocket.send(EOL.join(reply))
            return False

        # When we are here, we have a session
        # Point our socket to the sock attribute of HTTPConnection
        # (contained in the session), which contains the socket
        self.relaySocket = self.session.sock
        
        # Check if connection is still alive
        if not self.isConnectionAlive():
            LOG.error('HTTP: Relay connection is dead for session %s' % self.username)
            return False
            
        # Send the initial request to the server
        try:
            tosend = self.prepareRequest(data)
            self.relaySocket.send(tosend)
            # Send the response back to the client
            self.transferResponse()
            return True
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            LOG.error('HTTP: Failed to send initial request for session %s: %s' % (self.username, str(e)))
            return False

    def getHeaders(self, data):
        # Get the headers from the request, ignore first "header"
        # since this is the HTTP method, identifier, version
        headerSize = data.find(EOL+EOL)
        headers = data[:headerSize].split(EOL)[1:]
        headerDict = {}
        for header in headers:
            try:
                hdrKey = header.decode("ascii")
                if ':' in hdrKey:
                    parts = hdrKey.split(':', 1)
                    if len(parts) == 2:
                        headerDict[parts[0].lower()] = parts[1][1:]  # Remove leading space
            except UnicodeDecodeError:
                # Skip headers with non-ASCII characters
                continue
        return headerDict

    def transferResponse(self):
        try:
            data = self.relaySocket.recv(self.packetSize)
            if not data:
                LOG.debug('HTTP: No data received from relay socket - connection may be closed')
                return
                
            headerSize = data.find(EOL+EOL)
            if headerSize == -1:
                LOG.debug('HTTP: No complete headers found in response')
                self.socksSocket.send(data)
                return
                
            headers = self.getHeaders(data)
            try:
                bodySize = int(headers.get('content-length', 0))
                if bodySize > 0:
                    readSize = len(data)
                    # Make sure we send the entire response, but don't keep it in memory
                    self.socksSocket.send(data)
                    while readSize < bodySize + headerSize + 4:
                        try:
                            data = self.relaySocket.recv(self.packetSize)
                            if not data:
                                LOG.debug('HTTP: Connection closed while reading body')
                                break
                            readSize += len(data)
                            self.socksSocket.send(data)
                        except (ConnectionResetError, BrokenPipeError, OSError) as e:
                            LOG.debug('HTTP: Connection error while reading response body: %s' % str(e))
                            break
                else:
                    # No content-length, check for chunked encoding
                    if headers.get('transfer-encoding', '').lower() == 'chunked':
                        # Chunked transfer-encoding
                        LOG.debug('Server sent chunked encoding - transferring')
                        self.transferChunked(data, headers)
                    else:
                        # No body in the response, send as-is
                        self.socksSocket.send(data)
            except (ValueError, KeyError):
                # Error parsing content-length or other header issues
                LOG.debug('HTTP: Error parsing response headers, sending as-is')
                self.socksSocket.send(data)
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            LOG.debug('HTTP: Socket error in transferResponse: %s' % str(e))
            # Don't re-raise, let the caller handle the connection cleanup

    def transferChunked(self, data, _headers):
        try:
            headerSize = data.find(EOL+EOL)
            if headerSize == -1:
                LOG.debug('HTTP: Invalid chunked response - no headers')
                return

            self.socksSocket.send(data[:headerSize + 4])

            body = data[headerSize + 4:]
            if not body:
                LOG.debug('HTTP: No body data for chunked response')
                return
                
            # Size of the chunk
            try:
                eol_pos = body.find(EOL)
                if eol_pos == -1:
                    LOG.debug('HTTP: Invalid chunk size format')
                    return
                datasize = int(body[:eol_pos], 16)
            except ValueError:
                LOG.debug('HTTP: Cannot parse chunk size')
                return
                
            while datasize > 0:
                try:
                    # Size of the total body
                    bodySize = body.find(EOL) + 2 + datasize + 2
                    readSize = len(body)
                    # Make sure we send the entire response, but don't keep it in memory
                    self.socksSocket.send(body)
                    while readSize < bodySize:
                        maxReadSize = bodySize - readSize
                        try:
                            body = self.relaySocket.recv(min(self.packetSize, maxReadSize))
                            if not body:
                                LOG.debug('HTTP: Connection closed during chunked transfer')
                                return
                            readSize += len(body)
                            self.socksSocket.send(body)
                        except (ConnectionResetError, BrokenPipeError, OSError) as e:
                            LOG.debug('HTTP: Connection error during chunk read: %s' % str(e))
                            return
                    
                    try:
                        body = self.relaySocket.recv(self.packetSize)
                        if not body:
                            LOG.debug('HTTP: Connection closed while reading next chunk')
                            return
                        eol_pos = body.find(EOL)
                        if eol_pos == -1:
                            datasize = 0  # Exit loop if no EOL found
                        else:
                            datasize = int(body[:eol_pos], 16)
                    except (ValueError, ConnectionResetError, BrokenPipeError, OSError) as e:
                        LOG.debug('HTTP: Error reading chunk size: %s' % str(e))
                        return
                except Exception as e:
                    LOG.debug('HTTP: Error in chunked transfer loop: %s' % str(e))
                    return
                    
            LOG.debug('Last chunk received - exiting chunked transfer')
            try:
                self.socksSocket.send(body)
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                LOG.debug('HTTP: Error sending final chunk: %s' % str(e))
                
        except Exception as e:
            LOG.debug('HTTP: Unexpected error in transferChunked: %s' % str(e))

    def prepareRequest(self, data):
        # Parse the HTTP data, removing headers that break stuff
        response = []
        for part in data.split(EOL):
            # This means end of headers, stop parsing here
            if part == '':
                break
            # Remove the Basic authentication header
            if b'authorization' in part.lower():
                continue
            # Don't close the connection
            if b'connection: close' in part.lower():
                response.append('Connection: Keep-Alive')
                continue
            # If we are here it means we want to keep the header
            response.append(part)
        # Append the body
        response.append(b'')
        body_parts = data.split(EOL+EOL)
        if len(body_parts) > 1:
            response.append(body_parts[1])
        else:
            response.append(b'')  # No body for GET requests
        senddata = EOL.join(response)

        # Check if the body is larger than 1 packet
        headerSize = data.find(EOL+EOL)
        headers = self.getHeaders(data)
        try:
            bodySize = int(headers.get('content-length', 0))
            if bodySize > 0:
                readSize = len(data)
                while readSize < bodySize + headerSize + 4:
                    try:
                        additional_data = self.socksSocket.recv(self.packetSize)
                        if not additional_data:
                            LOG.debug('HTTP: Client closed connection while reading request body')
                            break
                        readSize += len(additional_data)
                        senddata += additional_data
                    except (ConnectionResetError, BrokenPipeError, OSError) as e:
                        LOG.debug('HTTP: Connection error while reading request body: %s' % str(e))
                        break
        except (KeyError, ValueError):
            # No body or invalid content-length, could be a simple GET or a POST without body
            # no need to check if we already have the full packet
            pass
        return senddata


    def tunnelConnection(self):
        while True:
            try:
                data = self.socksSocket.recv(self.packetSize)
                # If this returns with an empty string, it means the socket was closed
                if not data:
                    LOG.debug('HTTP: Client closed connection')
                    return
                    
                # Check for WebSocket upgrade requests in tunnel mode
                try:
                    headers = self.getHeaders(data)
                    if headers.get('upgrade', '').lower() == 'websocket':
                        LOG.debug('HTTP: WebSocket upgrade in tunnel - rejecting')
                        response = b'HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\nWebSocket not supported'
                        try:
                            self.socksSocket.send(response)
                        except:
                            pass
                        return
                except:
                    # Continue with normal processing if header parsing fails
                    pass
                    
                # Pass the request to the server
                tosend = self.prepareRequest(data)
                self.relaySocket.send(tosend)
                # Send the response back to the client
                self.transferResponse()
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                LOG.debug('HTTP: Connection error in tunnel: %s' % str(e))
                return
            except Exception as e:
                LOG.debug('HTTP: Unexpected error in tunnel: %s' % str(e))
                return
