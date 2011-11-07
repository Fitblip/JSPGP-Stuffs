<%@ page import="java.util.*" %>
<%@ page import="java.net.*" %>
<%@ page import="java.io.*" %>
<%
String email = request.getParameter("email");
String key = request.getParameter("key");
String html ="";

if (email != null){
       StringBuffer sbf = new StringBuffer();
        try {
                URL url = new URL("http://pgp.mit.edu:11371/pks/lookup?search=" + email + "&op=index");
                BufferedReader in = new BufferedReader(new InputStreamReader(url.openStream()));
                String inputLine;
                while ( (inputLine = in.readLine()) != null) sbf.append(inputLine);
                in.close();
        } catch (MalformedURLException e) {
        } catch (IOException e) {
        }
        html = sbf.toString();
        
} else if (key != null) {
       StringBuffer sbf = new StringBuffer();
        try {
                URL url = new URL("http://pgp.mit.edu:11371/pks/lookup?op=get&search=" + key);
                BufferedReader in = new BufferedReader(new InputStreamReader(url.openStream()));
                String inputLine;
                while ( (inputLine = in.readLine()) != null) sbf.append(inputLine +"\n");
                in.close();
        } catch (MalformedURLException e) {
        } catch (IOException e) {
        }
        html = sbf.toString();
            
} else {
    html = "No email specified!";       
}
%>
<%= html%>