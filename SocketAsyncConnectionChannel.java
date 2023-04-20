import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLHandshakeException;

public class SocketAsyncConnectionChannel {
    private static final int MAX_CONNECTION_ATTEMPTS = 3;
    private final String host;
    private final int port;
    private Socket socket;
    
    public SocketAsyncConnectionChannel(String host, int port) {
        this.host = host;
        this.port = port;
    }

    public void connect() throws IOException {
        int attempts = 0;
        while (attempts < MAX_CONNECTION_ATTEMPTS) {
            SSLSocket sslSocket = null;
            try {
                SSLContext sslContext = SSLContext.getDefault();
                SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
                SocketAddress socketAddress = new InetSocketAddress(host, port);
                sslSocket = (SSLSocket) sslSocketFactory.createSocket();
                sslSocket.setSoTimeout(5000); // Set a 5-second timeout
                sslSocket.connect(socketAddress);
                this.socket = sslSocket;
                break;
            } catch (SSLHandshakeException e) {
                throw new IOException("SSLHandshakeException occurred while connecting to the server. Reason: " + e.getMessage());
            } catch (IOException e) {
                attempts++;
                if (attempts >= MAX_CONNECTION_ATTEMPTS) {
                    throw new IOException("Failed to connect to the server after " + MAX_CONNECTION_ATTEMPTS + " attempts.", e);
                }
            } finally {
                if (sslSocket != null && !sslSocket.isConnected()) {
                    sslSocket.close();
                }
            }
        }
    }

    public void disconnect() {
        try {
            socket.close();
            logger.log(Level.INFO, "Successfully disconnected from the server.");
        } catch (IOException e) {
            logger.log(Level.WARNING, "IOException occurred while disconnecting from the server. Reason: " + e.getMessage());
        }
    }

    public boolean isConnected() {
        return socket != null && socket.isConnected();
    }
}
