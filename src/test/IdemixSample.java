/**
 * 
 */
package test;

import java.io.File;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.MessageDigest;

import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.TerminalFactory;

import net.sourceforge.scuba.smartcards.CommandAPDU;
import net.sourceforge.scuba.smartcards.TerminalCardService;
import service.IdemixService;

import com.ibm.zurich.credsystem.utils.Locations;
import com.ibm.zurich.idmx.dm.MasterSecret;
import com.ibm.zurich.idmx.dm.Values;
import com.ibm.zurich.idmx.dm.structure.AttributeStructure;
import com.ibm.zurich.idmx.dm.structure.CredentialStructure;
import com.ibm.zurich.idmx.issuance.IssuanceSpec;
import com.ibm.zurich.idmx.issuance.Issuer;
import com.ibm.zurich.idmx.issuance.Message;
import com.ibm.zurich.idmx.key.IssuerKeyPair;
import com.ibm.zurich.idmx.showproof.ProofSpec;
import com.ibm.zurich.idmx.showproof.Verifier;
import com.ibm.zurich.idmx.showproof.predicates.CLPredicate;
import com.ibm.zurich.idmx.showproof.predicates.Predicate;
import com.ibm.zurich.idmx.showproof.predicates.Predicate.PredicateType;
import com.ibm.zurich.idmx.utils.StructureStore;
import com.ibm.zurich.idmx.utils.SystemParameters;

/**
 * @author pim
 *
 */
public class IdemixSample {

    private static final int MAX_ATTR = 1;
    private static final int MAX_RUNS = 10;

    /** Actual location of the files. */
    public static final URI BASE_LOCATION = new File(
            System.getProperty("user.dir")).toURI().resolve("files/parameter/");

    /** Id that is used within the test files to identify the elements. */
    public static URI BASE_ID = null;
    
    /** Id that is used within the test files to identify the elements. */
    public static URI ISSUER_ID = null;
    static {
        try {
            BASE_ID = new URI("http://www.zurich.ibm.com/security/idmx/v2/");
            ISSUER_ID = new URI("http://www.issuer.com/");
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
    }
    
    /** Actual location of the public issuer-related files. */
    public static final URI ISSUER_LOCATION = BASE_LOCATION
            .resolve("../issuerData/");

    /**
     * Credential.<br/>
     * <ol>
     * <li>attr1:1313/ATTRIBUTE_VALUE_1</li>
     * <li>attr2:1314/ATTRIBUTE_VALUE_2</li>
     * <li>attr3:1315/ATTRIBUTE_VALUE_3</li>
     * <li>attr4:1316/ATTRIBUTE_VALUE_4</li>
     * <li>attr5:1317/ATTRIBUTE_VALUE_5</li>
     * </ol>
     * 
     * @see Test5Attributes#CRED_STRUCT_CARD
     */
    public static final String CREDCARD_FN = "Credential_perf";    

    /** Key pair of the issuer. */
    private static IssuerKeyPair issuerKey = null;

    /** Master secret to be used for this tests. */
    private static MasterSecret masterSecret = null;

	/**
	 * @param args
	 */
	@SuppressWarnings("unused")
	public static void main(String[] args) {
        System.out.println("Idemix MULTOS sample");

        try {
            // URIs and locations for issuer
            URI iskLocation = BASE_LOCATION.resolve("../private/isk.xml");
            URI ipkLocation = ISSUER_LOCATION.resolve("ipk.xml");

            issuerKey = Locations.initIssuer(BASE_LOCATION, BASE_ID.toString(),
                    iskLocation, ipkLocation, ISSUER_ID.resolve("ipk.xml"));

            URI masterSecretLocation = BASE_LOCATION.resolve("../private/ms.xml");
            masterSecret = Locations.loadMasterSecret(masterSecretLocation);
            if (masterSecret == null) {
                URI gp = BASE_ID.resolve("gp.xml");
                masterSecret = Locations.generateMasterSecret(gp,
                        masterSecretLocation);
            }
            
            Locations.initSystem(BASE_LOCATION, BASE_ID.toString());

            // loading issuer public key
            Locations.init(ISSUER_ID.resolve("ipk.xml"), ISSUER_LOCATION.resolve("ipk.xml"));

            // loading credential structures
            String credStruct = "CredStructPerf" + MAX_ATTR;
            loadCredStruct(credStruct);

        	
            /*
             * issuer parameters setup
             */

            // URIs and locations for recipient
            URI credStructLocation = null, credStructId = null;
            try {
                credStructLocation = BASE_LOCATION.resolve("../issuerData/"
                        + credStruct + ".xml");
                credStructId = new URI("http://www.ngo.org/" + credStruct + ".xml");
            } catch (URISyntaxException e) {
                e.printStackTrace();
            }

            // loading credential structure linked to a URI
            Locations.init(credStructId, credStructLocation);

            // create the issuance specification
            IssuanceSpec issuanceSpec = new IssuanceSpec(
                    ISSUER_ID.resolve("ipk.xml"), credStructId);

            MessageDigest hash = MessageDigest.getInstance("SHA-1");
            // get the values - NOTE: the values are KNOWN to both parties (as
            // specified in the credential structure)
            Values values = new Values(issuerKey.getPublicKey().getGroupParams()
                    .getSystemParams());
            values.add("attr1", new BigInteger(1, hash.digest("Alice Smith".getBytes())));
            values.add("attr2", new BigInteger(1, hash.digest("WA".getBytes())));
            if (MAX_ATTR > 2) {
            	values.add("attr3", new BigInteger(1, hash.digest("1010 Crypto Street".getBytes())));
	    }
	    if (MAX_ATTR > 3) {
            	values.add("attr4", new BigInteger(1, new byte[]{0x01}));
	    }
	    if (MAX_ATTR > 4) {
            	values.add("attr5", new BigInteger(1, new byte[]{0x49, (byte) 0x96, 0x02, (byte) 0xD2}));
            }

            /*
             *  token issuance
             */
            System.out.println("###");
            System.out.println("### Issuing Idemix credential");
            System.out.println("###");
            
            Issuer issuer = new Issuer(issuerKey, issuanceSpec, null, null, values);
            Message msgToRecipient1 = issuer.round0();

            // prover generates second issuance message
            TerminalFactory factory = TerminalFactory.getDefault();
            CardTerminals terminals = factory.terminals();
            CardTerminal terminal = terminals.list(CardTerminals.State.CARD_PRESENT).get(0);            
            if(!terminal.isCardPresent()) {
                throw new IllegalStateException("Card should be there, but it is not?");
            }
            IdemixService recipient = new IdemixService(new TerminalCardService(terminal), (short) MAX_ATTR);
            recipient.open();
            recipient.transmit(new CommandAPDU(0x00, 0x20, 0x00, 0x00, new byte[]{ 0x30, 0x30, 0x30, 0x30 }));
            recipient.setIssuanceSpecification(issuanceSpec);
            try {
            	recipient.generateMasterSecret();
            } catch (Exception e) {}
            recipient.setAttributes(issuanceSpec, values);
            Message msgToIssuer1 = recipient.round1(msgToRecipient1);

            // run the issuance protocol.             
            Message msgToRecipient2 = issuer.round2(msgToIssuer1);
            recipient.round3(msgToRecipient2);

            /*
             * token presentation
             */
            System.out.println("###");
            System.out.println("### Presenting an Idemix credential");
            System.out.println("###");
            
            // protocol parameters (shared by prover and verifier)
            String proofSpec = null;

            for (int r = 0; r < MAX_RUNS; r++) {
                System.out.println("\n\n\n\n### Run " + (r+1) + " of " + MAX_RUNS + "\n");
            for (int i = 0; i < Math.pow(2, MAX_ATTR); i++) {
        		proofSpec = "ProofSpecPerf" + MAX_ATTR + "-" + i;
                
                // prover generates the presentation proof
                // load the proof specification
                ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
                        BASE_LOCATION
                                .resolve("../proofSpecifications/" + proofSpec + ".xml"));

                Predicate predicate = spec.getPredicates().firstElement();
                if (predicate.getPredicateType() != PredicateType.CL) {
                    throw new RuntimeException("Unimplemented predicate.");
                }
                CLPredicate pred = ((CLPredicate) predicate);
                CredentialStructure cred = (CredentialStructure) StructureStore.getInstance().get(
                       pred.getCredStructLocation());

                // Determine the number of disclosed attributes
                int x = 0;
                for (AttributeStructure attribute : cred.getAttributeStructs()) {
                    if (pred.getIdentifier(attribute.getName()).isRevealed()) {
                    	x++;
                    }
                }
        		System.out.println("\n### Disclosing " + x + " attributes\n");

                System.out.println(spec.toStringPretty());

                SystemParameters sp = spec.getGroupParams().getSystemParams();

                // first get the nonce (done by the verifier)
                System.out.println("Getting nonce.");
                BigInteger nonce = Verifier.getNonce(sp);

                // create the proof
                recipient.open();
                recipient.transmit(new CommandAPDU(0x00, 0x20, 0x00, 0x00, new byte[]{ 0x30, 0x30, 0x30, 0x30 }));
                recipient.buildProof(nonce, spec);
                System.out.println("Proof Created.");
            }
            }
        } catch (Exception e) {
            System.out.println(e.toString());
            e.printStackTrace(System.out);
            return;
        }

        System.out.println("Sample completed successfully");
	}
	
    private static final void loadCredStruct(String credStructName) {
        URI credStructLocation = null, credStructId = null;
        try {
            credStructLocation = BASE_LOCATION
                    .resolve("../issuerData/" + credStructName + ".xml");
            credStructId = new URI("http://www.ngo.org/" + credStructName
                    + ".xml");
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }

        // loading credential structure linked to a URI
        Locations.init(credStructId, credStructLocation);
    }
}
