# Todos for the project
- Manage Docker, installed CLI tools
- Write methods that call CLI tools
- Methods for vulnerability database interaction
- Write test websites and APIs (server) for testing and demonstration
- UI

## Use
There are two methods of use:  
### Testing a server / API
- User enters ip or domain
- Find open ports
- Scan open ports for software versions
    - Check software for known vulnerabilities in vulnerability databases
    - Display known bugs to user, suggest an update
- Scan open ports for list of endpoints
    - Try endpoints for GET, POST, etc.

### testing a website / login page
- User enters ip or domain with path to html to test
- If html is an input form, try SQL injects  

At the end, a security report should be presented to the users listing the problems with their server or website.