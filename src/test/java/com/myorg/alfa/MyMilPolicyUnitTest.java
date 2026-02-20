package com.myorg.alfa;

import com.axiomatics.cr.alfa.test.junit.AlfaExtension;
import com.axiomatics.cr.alfa.test.junit.TestRequest;
import com.axiomatics.cr.alfa.test.junit.TestResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import static com.axiomatics.cr.alfa.test.junit.matchers.AlfaMatchers.permit;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;

public class MyMilPolicyUnitTest {

    @RegisterExtension
    public AlfaExtension alfa = new AlfaExtension().withMainPolicy("mil.defense.filebrowser.GlobalAccessControl");

    @Test
    public void generalsCanReadTopSecret() {
        TestRequest req = alfa.newTestRequest()
                .with("mil.defense.filebrowser.userRole", "general")
                .with("mil.defense.filebrowser.resourcePath", "/top-secret/doc1")
                .with("mil.defense.filebrowser.actionId", "read");

        TestResponse res = req.evaluate();
        assertThat(res, is(permit()));
    }

    @Test
    public void highClearanceSecureTerminalCanReadTopSecret() {
        TestRequest req = alfa.newTestRequest()
                .with("mil.defense.filebrowser.userRole", "soldier")
                .with("mil.defense.filebrowser.clearanceLevel", "3")
                .with("mil.defense.filebrowser.deviceType", "secure-terminal")
                .with("mil.defense.filebrowser.resourcePath", "/top-secret/doc1")
                .with("mil.defense.filebrowser.actionId", "read");

        TestResponse res = req.evaluate();
        assertThat(res, is(permit()));
    }

    @Test
    public void analystsCanReadOperations() {
        TestRequest req = alfa.newTestRequest()
                .with("mil.defense.filebrowser.userRole", "analyst")
                .with("mil.defense.filebrowser.resourcePath", "/operations/op1")
                .with("mil.defense.filebrowser.actionId", "read");

        TestResponse res = req.evaluate();
        assertThat(res, is(permit()));
    }

    @Test
    public void clearanceLevelTwoCannotReadTopSecret() {
        TestRequest req = alfa.newTestRequest()
                .with("mil.defense.filebrowser.userRole", "soldier")
                .with("mil.defense.filebrowser.clearanceLevel", "2")
                .with("mil.defense.filebrowser.deviceType", "secure-terminal")
                .with("mil.defense.filebrowser.resourcePath", "/top-secret/doc2")
                .with("mil.defense.filebrowser.actionId", "read");

        TestResponse res = req.evaluate();
        assertThat(res, is(not(permit())));
    }

    @Test
    public void highClearanceButNonSecureDeviceDenied() {
        TestRequest req = alfa.newTestRequest()
                .with("mil.defense.filebrowser.userRole", "soldier")
                .with("mil.defense.filebrowser.clearanceLevel", "3")
                .with("mil.defense.filebrowser.deviceType", "mobile")
                .with("mil.defense.filebrowser.resourcePath", "/top-secret/doc3")
                .with("mil.defense.filebrowser.actionId", "read");

        TestResponse res = req.evaluate();
        assertThat(res, is(not(permit())));
    }

    @Test
    public void fieldCommanderCanWriteOperations() {
        TestRequest req = alfa.newTestRequest()
                .with("mil.defense.filebrowser.userRole", "field-commander")
                .with("mil.defense.filebrowser.resourcePath", "/operations/op2")
                .with("mil.defense.filebrowser.actionId", "write");

        TestResponse res = req.evaluate();
        assertThat(res, is(permit()));
    }

    @Test
    public void unknownActionIsDenied() {
        TestRequest req = alfa.newTestRequest()
                .with("mil.defense.filebrowser.userRole", "general")
                .with("mil.defense.filebrowser.resourcePath", "/top-secret/doc4")
                .with("mil.defense.filebrowser.actionId", "delete");

        TestResponse res = req.evaluate();
        assertThat(res, is(not(permit())));
    }

    @Test
    public void publicDocsSoldierCanRead() {
        TestRequest req = alfa.newTestRequest()
                .with("mil.defense.filebrowser.userRole", "soldier")
                .with("mil.defense.filebrowser.resourcePath", "/public/doc2")
                .with("mil.defense.filebrowser.actionId", "read");

        TestResponse res = req.evaluate();
        assertThat(res, is(permit()));
    }

    @Test
    public void suspendedUsersAreDenied() {
        TestRequest req = alfa.newTestRequest()
                .with("mil.defense.filebrowser.userRole", "suspended")
                .with("mil.defense.filebrowser.resourcePath", "/public/doc1")
                .with("mil.defense.filebrowser.actionId", "read");

        TestResponse res = req.evaluate();
        assertThat(res, is(not(permit())));
    }
}
