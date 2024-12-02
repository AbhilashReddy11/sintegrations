package in.gov.enam.integrations.controller;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.sql.Date;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Response.Status;

import org.apache.commons.lang3.StringUtils;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import in.gov.enam.integrations.contants.Constants;
import in.gov.enam.integrations.dao.BankAuthenticationDAO;
import in.gov.enam.integrations.dao.CommonDAO;
import in.gov.enam.integrations.exception.IntegrationsException;
import in.gov.enam.integrations.to.ReqResDTO;
import in.gov.enam.integrations.to.ResponseDTO;
import in.gov.enam.integrations.util.CommonUtils;
import in.gov.enam.integrations.util.RsaShaEncDec;
import in.gov.enam.integrations.vo.LoginCredentials;
import in.gov.enam.integrations.vo.ReconcileDetails;
import in.gov.enam.integrations.vo.RefundDetails;
import in.gov.enam.integrations.vo.SettlementDetails;
import in.gov.enam.integrations.vo.TransactionInfo;


@RestController
@RequestMapping("/bank")
public class SBIController {
	@Autowired
	RsaShaEncDec encdec;
    private static final Logger logger = LoggerFactory.getLogger(SBIController.class);

	//our public key
	//use their public key to encrypt
    public static final String publicKeyPath;
    public static final String privateKeyPath;

    static {
        if (System.getProperty("os.name").toLowerCase().contains("win")) {
            // Windows paths
//            publicKeyPath = "C:\\Users\\yennapu.abhilash\\Downloads\\public.pem";
//            privateKeyPath = "C:\\Users\\yennapu.abhilash\\Downloads\\private.key";
        	 publicKeyPath = "C:\\eNAM\\openssl\\publickey.cer";
             privateKeyPath = "C:\\eNAM\\openssl\\private_key_pkcs8.pem";
        } else {
            // Linux paths
            publicKeyPath = "/home/spandana/sbi/keys/public.cer";
            System.out.println(" publicKeyPath + :" + publicKeyPath);
            privateKeyPath = "/home/spandana/sbi/keys/private.pem";
            System.out.println(" publicKeyPath + :" + privateKeyPath);
        }
    }
	
	@PostMapping("/loginController")
	public ReqResDTO authenticateUser(@RequestBody ReqResDTO reqDTO,HttpServletRequest request) throws Exception {
		ResponseDTO response = new ResponseDTO();
	//	JSONObject jsonReq = new JSONObject();;
		JSONObject payload = null;
	//	JSONObject signature = new JSONObject();
		String encData=reqDTO.getData();
		String encSessionKey=reqDTO.getSessionKey();
		String decSessionKey=encdec.decryptRSA(encSessionKey, privateKeyPath);
		String decData=encdec.decryptAES(encData, decSessionKey);
		try {
			payload = new JSONObject(decData);
			System.out.println("payload  :" +payload);
			//for SBI
			if (!payload.has("loginDetails") || payload.getJSONObject("loginDetails").isEmpty()) {
				response.setMessageCode(Constants.STATUS_FAILED);
				response.setMessage("missing bank details");
				response.setStatus(Status.OK);
				return encResponse(response);
			}
			if (!payload.has("hash") || payload.getString("hash").isEmpty()) {
				response.setMessageCode(Constants.STATUS_FAILED);
				response.setMessage("missing bank details");
				response.setStatus(Status.OK);
				return encResponse(response);
			}
			JSONObject jsonReq = payload.getJSONObject("loginDetails");
			 System.out.println("data  :" +jsonReq.toString());
			 String signature = payload.getString("hash");
			 System.out.println("signature  :" +signature);
    
			if (!jsonReq.has("bankId") || jsonReq.getString("bankId").isEmpty()) {
				response.setMessageCode(Constants.STATUS_FAILED);
				response.setMessage(Constants.MISSING_BANKID);
				response.setStatus(Status.OK);
				return encResponse(response);
			}

			if (jsonReq.getString("bankId").length() > 50) {
				response.setMessageCode(Constants.STATUS_FAILED);
				response.setMessage(Constants.BANKID_SIZE);
				response.setStatus(Status.OK);
				return encResponse(response);
			}

			if (!jsonReq.has("loginKey") || jsonReq.getString("loginKey").isEmpty()) {
				response.setMessageCode(Constants.STATUS_FAILED);
				response.setMessage(Constants.MISSING_lOGINKEY);
				response.setStatus(Status.OK);
				return encResponse(response);
			}
			boolean isSignVerified=encdec.verifySign(jsonReq.toString(), signature, publicKeyPath);
			 System.out.println("result  :" +isSignVerified);
			if(isSignVerified == false) {
				response.setMessageCode(Constants.STATUS_FAILED);
				response.setMessage("Inavlid signature");
				response.setStatus(Status.OK);
				return encResponse(response);
			}

			ObjectMapper mapper = new ObjectMapper();
			LoginCredentials user = mapper.readValue(jsonReq.toString(), LoginCredentials.class);

			String bankId = user.getBankId().trim();
			String loginKey = user.getLoginKey().trim();
			boolean isExists = false;
			String token = null;
			response.setId(bankId);

			/*
			 * Authenticate bankId and loginKey
			 */
			BankAuthenticationDAO bankAuthDao = new BankAuthenticationDAO();
			isExists = bankAuthDao.checkBankIdAndLoginKey(bankId, loginKey);

			if (isExists) {

				if (bankAuthDao.checkUserINTokenDatabase(bankId) == null) {
					token = bankAuthDao.newUser(bankId); // Generating new Token

				} else {
					token = bankAuthDao.updateCurrentUserTokenValidity(bankId); // Extending token validity
					logger.info("Login Time: " + new Timestamp(System.currentTimeMillis()));

				}

				// save bank ip
				CommonDAO commonDao = new CommonDAO();
				commonDao.saveClientIP(bankId, request);

				response.setId(bankId);
				response.setMessage(token);
				response.setMessageCode(Constants.STATUS_SUCCESS);

				Date today = new Date((new java.util.Date()).getTime());
				Long transId = CommonDAO.getMaxNoInternal(Constants.CHAR_1, "RESTREADTRANSID", today, Constants.CHAR_1);
				writeFileData(null, response, "LoginData_", "/loginController", null, decData, bankId,
					transId.toString());
				response.setStatus(Status.OK);
				return encResponse(response);

			} else {
				logger.error("Error:Login --> Invalid Login Credentials");
				response.setStatus(Status.UNAUTHORIZED);
				response.setId(bankId);
				response.setMessageCode(Constants.STATUS_FAILED);
				response.setMessage("Invalid BankId / LoginKey");
				return encResponse(response);
			}

		} catch (Exception e) {
			e.printStackTrace();
			logger.error(e.toString());
			response.setStatus(Status.INTERNAL_SERVER_ERROR);
			response.setMessage("Network Error");
			response.setMessageCode( Constants.STATUS_FAILED);
			return encResponse(response);
		}

	}
	
	
	
	
	@PostMapping("/postTransactionInfo")
	public ReqResDTO postTransactionInfo( @RequestHeader("Authorization") String authorizationHeader,
            @RequestBody ReqResDTO reqDTO, HttpServletRequest request) throws Exception {
		
		ResponseDTO response = new ResponseDTO();
		String encData=reqDTO.getData();
		String encSessionKey=reqDTO.getSessionKey();
		String decSessionKey=encdec.decryptRSA(encSessionKey, privateKeyPath);
		String decData=encdec.decryptAES(encData, decSessionKey);

		BankAuthenticationDAO bankAuthDao = new BankAuthenticationDAO();
		String token = authorizationHeader.substring("Bearer".length()).trim();

     	Date today = new Date((new java.util.Date()).getTime());
		Long transId = CommonDAO.getMaxNoInternal(Constants.CHAR_1, "RESTREADTRANSID", today, Constants.CHAR_1);
		ObjectMapper objectMapper = new ObjectMapper();
		List<TransactionInfo> transList=null;
		 try {
	             transList = objectMapper.readValue(decData, new TypeReference<List<TransactionInfo>>() {});
	           logger.info(transList.toString());
	           transList.forEach(obj -> System.out.println(obj.toString() +"\n"));
	        } catch (Exception e) {
	        	logger.error(e.toString());
	            e.printStackTrace();
	        }

		try {
			Gson gson = new Gson();
		JSONObject jsonReq = new JSONObject( "{ \"transList\":" + decData + "}"  );
			JSONArray jsonArray = jsonReq.getJSONArray("transList");

			if (jsonArray != null && jsonArray.length() > 0) {
				for (int i = 0; i < jsonArray.length(); i++) {

					jsonReq = jsonArray.getJSONObject(i);
					response = CommonUtils.validatePostTransInfoReq(jsonReq);
					response.setId(transId.toString());

					if (StringUtils.isNotBlank(response.getMessageCode())) {
						response.setStatus(Status.OK);
						return encResponse(response);
					}
				}
			}

			List<String> bankIds = bankAuthDao.fetchBankIds(transList);

			if (!StringUtils.isBlank(token)) {
				String bankIdFrmToken = bankAuthDao.validateToken(token);

				if (!StringUtils.isBlank(bankIdFrmToken)) {

					for (String bankId : bankIds) {
						if (!bankId.equals(bankIdFrmToken)) {
							response.setStatus(Status.UNAUTHORIZED);
							response.setId(transId.toString());
							response.setMessageCode(Constants.STATUS_FAILED);
							response.setMessage("Incorrect Bank Id");
							return encResponse(response);
   
						}
					}
					response = bankAuthDao.postTransacationData(transList);
					writeFileData(jsonArray, response, "PostTransInfo_", "/postTransactionInfo", null, null,
							bankIds.get(0), response.getId());
					response.setStatus(Status.OK);
					return encResponse(response);
				} else {
                     response.setStatus(Status.UNAUTHORIZED);
                     response.setId(transId.toString());
                     response.setMessageCode(Constants.STATUS_FAILED);
                     response.setMessage("Invalid Token");
                     return encResponse(response);
				}
			} else {
				 response.setId(transId.toString());
                 response.setMessageCode(Constants.STATUS_FAILED);
                 response.setMessage("Please provide Token");
                 return encResponse(response);
			}

			
		} catch (Exception e) {
			e.printStackTrace();
			logger.error(e.toString());
			 response.setId(transId.toString());
             response.setMessageCode(Constants.STATUS_FAILED);
             response.setMessage("Internal Server Error");
             return encResponse(response);
		}
	}
	
	
	
	
	@PostMapping("/escrowcollectionupload")
	public ReqResDTO postEscrowCollection( @RequestHeader("Authorization") String authorizationHeader,
			@RequestBody ReqResDTO reqDTO, HttpServletRequest request) throws Exception {
	
		ResponseDTO response = new ResponseDTO();
		String encData=reqDTO.getData();
		String encSessionKey=reqDTO.getSessionKey();
		String decSessionKey=encdec.decryptRSA(encSessionKey, privateKeyPath);
		String decData=encdec.decryptAES(encData, decSessionKey);
		System.out.println("Request Json for postEscrowCollection():\n");

		BankAuthenticationDAO bankAuthDao = new BankAuthenticationDAO();
		String token = authorizationHeader.substring("Bearer".length()).trim();
		ObjectMapper objectMapper = new ObjectMapper();
		List<TransactionInfo> paymentList=null;
		 try {
			 paymentList = objectMapper.readValue(decData, new TypeReference<List<TransactionInfo>>() {});
			logger.info(paymentList.toString());
	        } catch (Exception e) {
	        	logger.error(e.toString());
	            e.printStackTrace();
	        }
		Date today = new Date((new java.util.Date()).getTime());
		Long maxno = CommonDAO.getMaxNoInternal(Constants.CHAR_1, "RESTREADTRANSID", today, Constants.CHAR_1);

		try {
			Gson gson = new Gson();
			String jsonString = gson.toJson(paymentList);
			JSONObject jsonReq = new JSONObject("{ \"paymentList\":" + jsonString + "}");
			JSONArray jsonArray = jsonReq.getJSONArray("paymentList");

			if (jsonArray != null && jsonArray.length() > 0) {
				for (int i = 0; i < jsonArray.length(); i++) {

					jsonReq = jsonArray.getJSONObject(i);
					response = CommonUtils.validateRequest(jsonReq, Constants.ESCROW);
					response.setId(maxno.toString());

					if (StringUtils.isNotBlank(response.getMessageCode())) {
						response.setStatus(Status.OK);
						return encResponse(response);
					}
				}
			}

			List<String> bankIds = bankAuthDao.fetchBankIds(paymentList);

			if (!StringUtils.isBlank(token)) {
				String bankIdFrmToken = bankAuthDao.validateToken(token);
				if (!StringUtils.isBlank(bankIdFrmToken)) {

					for (String bankId : bankIds) {
						if (!bankId.equals(bankIdFrmToken)) {
							response.setStatus(Status.UNAUTHORIZED);
							response.setId(maxno.toString());
							response.setMessageCode(Constants.STATUS_FAILED);
							response.setMessage("Incorrect Bank Id");
							return encResponse(response);
						}
					}
					response = bankAuthDao.postEscrowCollectionData(paymentList);
					writeFileData(jsonArray, response, "EscrowColl_", "/escrowcollectionupload", null, null,
							bankIds.get(0), response.getId());
					response.setStatus(Status.OK);
					return encResponse(response);

				} else {
					response.setStatus(Status.UNAUTHORIZED);
					response.setId(maxno.toString());
					response.setMessageCode(Constants.STATUS_FAILED);
					response.setMessage("Invalid Token");
					return encResponse(response);
				}
			} else {
				response.setStatus(Status.UNAUTHORIZED);
				response.setId(maxno.toString());
				response.setMessageCode(Constants.STATUS_FAILED);
				response.setMessage("Please provide Token");
				return encResponse(response);
			}

		} catch (Exception e) {
			e.printStackTrace();
			logger.error(e.toString());
			response.setStatus(Status.INTERNAL_SERVER_ERROR);
			response.setId(maxno.toString());
			response.setMessageCode(Constants.STATUS_FAILED);
			response.setMessage("Internal Server Error");
			return encResponse(response);
			
		}

	}
	

	@PostMapping("/validateInvoiceDetails")
	public List<ReqResDTO> validateInvoice( @RequestHeader("Authorization") String authorizationHeader,
			@RequestBody ReqResDTO reqDTO, HttpServletRequest request) throws Exception {
	
		ResponseDTO response = new ResponseDTO();
		String encData=reqDTO.getData();
		String encSessionKey=reqDTO.getSessionKey();
		String decSessionKey=encdec.decryptRSA(encSessionKey, privateKeyPath);
		String decData=encdec.decryptAES(encData, decSessionKey);
		System.out.println("Request Json for validateInvoice():\n");

		BankAuthenticationDAO bankAuthDao = new BankAuthenticationDAO();
		String token = authorizationHeader.substring("Bearer".length()).trim();
		String bankTranId = null;
		ObjectMapper objectMapper = new ObjectMapper();
		List<TransactionInfo> transList=null;
		List<ReqResDTO> lstResponse = new ArrayList<ReqResDTO>();
		 try {
			 transList = objectMapper.readValue(decData, new TypeReference<List<TransactionInfo>>() {});
			 logger.info(transList.toString());
	        } catch (Exception e) {
	            e.printStackTrace();
	        }

		try {
			Gson gson = new Gson();
			JSONObject jsonReq = new JSONObject("{ \"transList\":" + decData + "}");
			JSONArray jsonArray = jsonReq.getJSONArray("transList");

			if (transList.get(0).getBanktrnId() != null) {
				bankTranId = transList.get(0).getBanktrnId();
			}

			/*
			 * if(jsonReq.has("banktrnId")) { bankTranId = jsonReq.getString("banktrnId"); }
			 */

			if (jsonArray != null && jsonArray.length() > 0) {
				for (int i = 0; i < jsonArray.length(); i++) {

					jsonReq = jsonArray.getJSONObject(i);
					response = CommonUtils.validateRequest(jsonReq, Constants.VALIDINVOICE);

					if (StringUtils.isNotBlank(response.getMessageCode())) {
						response.setStatus(Status.OK);
						ReqResDTO reqResDTO= encResponse(response);
						lstResponse.add(reqResDTO);
						return lstResponse;
//						return Response.status(Status.OK).entity(response).build();
					}
				}
			}

			List<String> bankIds = bankAuthDao.fetchBankIds(transList);

			if (!StringUtils.isBlank(token)) {
				String bankIdFrmToken = bankAuthDao.validateToken(token);

				if (!StringUtils.isBlank(bankIdFrmToken)) {

					for (String bankId : bankIds) {
						if (!bankId.equals(bankIdFrmToken)) {
							response.setStatus(Status.UNAUTHORIZED);
							response.setMessageCode(Constants.STATUS_FAILED);
							response.setMessage("Incorrect Bank Id");
							response.setId(bankTranId);
		
							lstResponse.add(encResponse(response));
							return lstResponse;
						}
					}
					/*
					 * Validation of Invoice No and Amount
					 */
					List<ResponseDTO> responseList = bankAuthDao.validateInvoiceData(transList);

					Date today = new Date((new java.util.Date()).getTime());
					Long transId = CommonDAO.getMaxNoInternal(Constants.CHAR_1, "RESTREADTRANSID", today,
							Constants.CHAR_1);

					writeFileData(jsonArray, null, "ValidateInvoice_", "/validateInvoiceDetails", responseList, null,
							bankIds.get(0), transId.toString());
					for (ResponseDTO res : responseList) {
						res.setStatus(Status.OK);
						lstResponse.add(encResponse(res));
						
					}
					
                    return lstResponse;
				} else {
					response.setStatus(Status.UNAUTHORIZED);
					response.setMessageCode(Constants.STATUS_FAILED);
					response.setMessage("Invalid Token");
					response.setId(bankTranId);

					lstResponse.add(encResponse(response));
					return lstResponse;
				}
				
			} else {

				response.setStatus(Status.UNAUTHORIZED);
				response.setMessageCode(Constants.STATUS_FAILED);
				response.setMessage("Please provide Token");
				response.setId(bankTranId);

				lstResponse.add(encResponse(response));
				return lstResponse;
		
			}

		} catch (Exception e) {
			e.printStackTrace();
	     	logger.error(e.toString());
			response.setStatus(Status.INTERNAL_SERVER_ERROR);
			response.setMessageCode(Constants.STATUS_FAILED);
			response.setMessage("Internal Server Error");
			response.setId(bankTranId);

			lstResponse.add(encResponse(response));
			return lstResponse;
	}
		}
	
	
	@PostMapping("/settlementRejections")
	public ReqResDTO postSettlementRejections( @RequestHeader("Authorization") String authorizationHeader,
			@RequestBody ReqResDTO reqDTO, HttpServletRequest request) throws Exception {	
		ResponseDTO response = new ResponseDTO();
		String encData=reqDTO.getData();
		String encSessionKey=reqDTO.getSessionKey();
		String decSessionKey=encdec.decryptRSA(encSessionKey, privateKeyPath);
		String decData=encdec.decryptAES(encData, decSessionKey);
		 Gson g = new Gson();
	        JsonObject payloadGson = g.fromJson(decData, JsonObject.class);

            JSONObject payload = new JSONObject(decData);
		// Create JSONObject from LinkedHashMap
		if (!payload.has("rejectedSettlementDetails") || payload.getJSONObject("rejectedSettlementDetails").isEmpty()) {
			response.setMessageCode(Constants.STATUS_FAILED);
			response.setMessage("missing rejectedSettlementDetails");
			response.setStatus(Status.OK);
			return encResponse(response);
		}
		if (!payload.has("hash") || payload.getString("hash").isEmpty()) {
			response.setMessageCode(Constants.STATUS_FAILED);
			response.setMessage("missing signature");
			response.setStatus(Status.OK);
			return encResponse(response);
		}

        JsonArray settlementRejCanListArray = payloadGson.getAsJsonObject("rejectedSettlementDetails")
                .getAsJsonArray("settlementRejCanList");
        String details=settlementRejCanListArray.toString();
        String data="{\"settlementRejCanList\":"+details+"}";
//        JSONObject jsonReq = new JSONObject();
//        jsonReq.put("rejectedSettlementDetails", settlementRejCanListArray);	
       	JSONObject jsonReq = payload.getJSONObject("rejectedSettlementDetails");
		 String signature = payload.getString("hash");
		 System.out.println("signature  :" +signature);
		 boolean isSignVerified=encdec.verifySign(data, signature, publicKeyPath);
		 System.out.println("result  :" +isSignVerified);
		if(isSignVerified == false) {
			response.setMessageCode(Constants.STATUS_FAILED);
			response.setMessage("Inavlid signature");
			response.setStatus(Status.OK);
			return encResponse(response);
		}
		BankAuthenticationDAO bankAuthDao = new BankAuthenticationDAO();
		String token = authorizationHeader.substring("Bearer".length()).trim();
		Date today = new Date((new java.util.Date()).getTime());
		Long transId = CommonDAO.getMaxNoInternal(Constants.CHAR_1, "RESTREADTRANSID", today, Constants.CHAR_1);
    	ObjectMapper objectMapper = new ObjectMapper();

		try {

		//	JSONObject jsonReq = new JSONObject("{ \"settlementRejCanList\":" + decData + "}");
			JSONArray jsonArray = jsonReq.getJSONArray("settlementRejCanList");
			List<SettlementDetails> settlementRejCanList = new ArrayList<SettlementDetails>();
			 try {
				 settlementRejCanList = objectMapper.readValue(jsonArray.toString(), new TypeReference<List<SettlementDetails>>() {});
				 logger.info(settlementRejCanList.toString());
		        } catch (Exception e) {
		            e.printStackTrace();
		        }

			if (jsonArray != null && jsonArray.length() > 0) {
				for (int i = 0; i < jsonArray.length(); i++) {

					jsonReq = jsonArray.getJSONObject(i);
					response = CommonUtils.validateSettlementDetails(jsonReq, Constants.SETTLEMENTREJ);
					response.setId(transId.toString());

					if (StringUtils.isNotBlank(response.getMessageCode())) {
						response.setStatus(Status.OK);
						return encResponse(response);
					}
				}
			}

			List<String> bankIds = bankAuthDao.fetchBankIds(settlementRejCanList);

			if (!StringUtils.isBlank(token)) {
				String bankIdFrmToken = bankAuthDao.validateToken(token);

				if (!StringUtils.isBlank(bankIdFrmToken)) {

					for (String bankId : bankIds) {
						if (!bankId.equals(bankIdFrmToken)) {
							response.setStatus(Status.INTERNAL_SERVER_ERROR);
							response.setMessageCode(Constants.STATUS_FAILED);
							response.setMessage("Incorrect Bank Id");
							response.setId(transId.toString());
							return encResponse(response);
						}
					}
					response = bankAuthDao.postSettlementRejectionsData(settlementRejCanList);
					writeFileData(jsonArray, response, "SettlementRej_", "/settlementRejections", null, null,
							bankIds.get(0), response.getId());
					response.setStatus(Status.INTERNAL_SERVER_ERROR);
					return encResponse(response);

				} else {
					response.setStatus(Status.INTERNAL_SERVER_ERROR);
					response.setMessageCode(Constants.STATUS_FAILED);
					response.setMessage("Invalid Token");
					response.setId(transId.toString());
					 return encResponse(response);	
				}
			} else {
				response.setStatus(Status.UNAUTHORIZED);
				response.setMessageCode(Constants.STATUS_FAILED);
				response.setMessage("Please provide Token");
				response.setId(transId.toString());
				 return encResponse(response);	
			}

		} catch (Exception e) {
			e.printStackTrace();
			logger.error(e.toString());
			response.setStatus(Status.INTERNAL_SERVER_ERROR);
			response.setMessageCode(Constants.STATUS_FAILED);
			response.setMessage("Internal Server Error");
			response.setId(transId.toString());
			 return encResponse(response);	
		}
	}

	
	
   @PostMapping("/uploadSettlementStatusDetails")
	public ReqResDTO postSettlementStatusDetails( @RequestHeader("Authorization") String authorizationHeader,
			@RequestBody ReqResDTO reqResDTO) throws Exception {
	   System.out.println(reqResDTO.toString());
		String decSessionKey=encdec.decryptRSA(reqResDTO.getSessionKey(), privateKeyPath);
		String decData=encdec.decryptAES(reqResDTO.getData(), decSessionKey);
		System.out.println("Request Json for postSettlementStatusDetails() :\n");
		System.out.println(decData);
		Gson g = new Gson();
        JsonObject payloadGson = g.fromJson(decData, JsonObject.class);
    	ResponseDTO response = new ResponseDTO();

        JSONObject payload = new JSONObject(decData);
	// Create JSONObject from LinkedHashMap
	if (!payload.has("settlementStatusDetails") || payload.getJSONObject("settlementStatusDetails").isEmpty()) {
		response.setMessageCode(Constants.STATUS_FAILED);
		response.setMessage("missing settlementStatusDetails");
		response.setStatus(Status.OK);
		return encResponse(response);
	}
	if (!payload.has("hash") || payload.getString("hash").isEmpty()) {
		response.setMessageCode(Constants.STATUS_FAILED);
		response.setMessage("missing signature");
		response.setStatus(Status.OK);
		return encResponse(response);
	}

    JsonArray settlementRejCanListArray = payloadGson.getAsJsonObject("settlementStatusDetails")
            .getAsJsonArray("settlementStatusList");
    String details=settlementRejCanListArray.toString();
    String data="{\"settlementStatusList\":"+details+"}";
    JSONObject jsonReq = payload.getJSONObject("settlementStatusDetails");
	 String signature = payload.getString("hash");
	 System.out.println("signature  :" +signature);
	 boolean isSignVerified=encdec.verifySign(data, signature, publicKeyPath);
	 System.out.println("result  :" +isSignVerified);
	if(isSignVerified == false) {
		response.setMessageCode(Constants.STATUS_FAILED);
		response.setMessage("Inavlid signature");
		response.setStatus(Status.OK);
		return encResponse(response);
	}

		List<SettlementDetails> settlementStatusList = new ArrayList<SettlementDetails>();
	

		BankAuthenticationDAO bankAuthDao = new BankAuthenticationDAO();
		String token = authorizationHeader.substring("Bearer".length()).trim();

		Date today = new Date((new java.util.Date()).getTime());
		Long transId = CommonDAO.getMaxNoInternal(Constants.CHAR_1, "RESTREADTRANSID", today, Constants.CHAR_1);

		try {

	//		Gson gson = new Gson();

		//	JSONObject jsonReq = new JSONObject("{ \"settlementStatusList\":" + decData + "}");

			JSONArray jsonArray = jsonReq.getJSONArray("settlementStatusList");
			ObjectMapper objectMapper = new ObjectMapper();
			 try {
				 settlementStatusList = objectMapper.readValue(jsonArray.toString(), new TypeReference<List<SettlementDetails>>() {});
				logger.info(settlementStatusList.toString());
		        } catch (Exception e) {
		            e.printStackTrace();
		            logger.error(e.toString());
		        }

			if (jsonArray != null && jsonArray.length() > 0) {
				for (int i = 0; i < jsonArray.length(); i++) {

					jsonReq = jsonArray.getJSONObject(i);
					response = CommonUtils.validateSettlementDetails(jsonReq, Constants.SETTLEMENTSTATUS);
					response.setId(transId.toString());

					if (StringUtils.isNotBlank(response.getMessageCode())) {
						response.setStatus(Status.OK);
						return encResponse(response);	
					}
				}
			}

			List<String> bankIds = bankAuthDao.fetchBankIds(settlementStatusList);

			if (!StringUtils.isBlank(token)) {
				String bankIdFrmToken = bankAuthDao.validateToken(token);

				if (!StringUtils.isBlank(bankIdFrmToken)) {

					for (String bankId : bankIds) {
						if (!bankId.equals(bankIdFrmToken)) {
							response.setStatus(Status.UNAUTHORIZED);
							response.setMessageCode(Constants.STATUS_FAILED);
							response.setMessage("Incorrect Bank Id");
							response.setId(transId.toString());
							 return encResponse(response);	
						}
					}
					response = bankAuthDao.postSettlementRejectionsData(settlementStatusList);
					writeFileData(jsonArray, response, "SettlementStatus_", "/uploadSettlementStatusDetails", null,
							null, bankIds.get(0), response.getId());
					response.setStatus(Status.OK);
					 return encResponse(response);	

				} else {
					response.setStatus(Status.UNAUTHORIZED);
					response.setMessageCode(Constants.STATUS_FAILED);
					response.setMessage("Invalid Token");
					response.setId(transId.toString());
					 return encResponse(response);	
				}
			} else {

				response.setStatus(Status.UNAUTHORIZED);
				response.setMessageCode(Constants.STATUS_FAILED);
				response.setMessage( "Please provide Token");
				response.setId(transId.toString());
				 return encResponse(response);	
			}

		} catch (Exception e) {
			e.printStackTrace();
			logger.error(e.toString());
			response.setStatus(Status.INTERNAL_SERVER_ERROR);
			response.setMessageCode(Constants.STATUS_FAILED);
			response.setMessage("Internal Server Error");
			response.setId(transId.toString());
			 return encResponse(response);			
		}
	}

   
   
	@PostMapping("/reconcileDetails")
	public ReqResDTO postReconcileDetails(@RequestHeader("Authorization") String authorizationHeader,
			@RequestBody ReqResDTO reqDTO, HttpServletRequest request) throws Exception {
		ReconcileDetails reconcileDetails=null;
		JSONObject jsonReq =null;
		ResponseDTO response = new ResponseDTO();
		String encData=reqDTO.getData();
		String encSessionKey=reqDTO.getSessionKey();
		String decSessionKey=encdec.decryptRSA(encSessionKey, privateKeyPath);
		String decData=encdec.decryptAES(encData, decSessionKey);
		BankAuthenticationDAO bankAuthDao = new BankAuthenticationDAO();
		String token = authorizationHeader.substring("Bearer".length()).trim();
		ObjectMapper objectMapper = new ObjectMapper();

        JSONObject payload = new JSONObject(decData);
	// Create JSONObject from LinkedHashMap
	if (!payload.has("reconcileDetails") || payload.getJSONObject("reconcileDetails").isEmpty()) {
		response.setMessageCode(Constants.STATUS_FAILED);
		response.setMessage("missing reconcileDetails");
		response.setStatus(Status.OK);
		return encResponse(response);
	}
	if (!payload.has("hash") || payload.getString("hash").isEmpty()) {
		response.setMessageCode(Constants.STATUS_FAILED);
		response.setMessage("missing signature");
		response.setStatus(Status.OK);
		return encResponse(response);
	}
	JsonNode jsonNode = objectMapper.readTree(decData);
	JsonNode reconcileDetailsNode = jsonNode.get("reconcileDetails");
//    JsonArray settlementRejCanListArray = payloadGson.getAsJsonObject("reconcileDetails")
//            .getAsJsonArray("transactionDebits");
  //  String details=settlementRejCanListArray.toString();
 //   String data="{\"settlementStatusList\":"+details+"}";
     jsonReq = payload.getJSONObject("reconcileDetails");
	 String signature = payload.getString("hash");
	 System.out.println("signature  :" +signature);
	 boolean isSignVerified=encdec.verifySign(reconcileDetailsNode.toString(), signature, publicKeyPath);
	 System.out.println("result  :" +isSignVerified);
	if(isSignVerified == false) {
		response.setMessageCode(Constants.STATUS_FAILED);
		response.setMessage("Inavlid signature");
		response.setStatus(Status.OK);
		return encResponse(response);
	}

//		 try {
//			 reconcileDetails = objectMapper.readValue(decData, new TypeReference<ReconcileDetails>() {});
//			logger.info(reconcileDetails.toString());
//	        } catch (Exception e) {
//	        	logger.error(e.toString());
//	            e.printStackTrace();
//	            
//	        }
		Date today = new Date((new java.util.Date()).getTime());
		Long transId = CommonDAO.getMaxNoInternal(Constants.CHAR_1, "RESTREADTRANSID", today, Constants.CHAR_1);

		
		
		
		try {
			Gson gson = new Gson();
			String bankId = null;
			String jsonString = gson.toJson(reconcileDetails);
		//	JSONObject jsonReq = new JSONObject(jsonString);

			if (!StringUtils.isBlank(token)) {
				String bankIdFrmToken = bankAuthDao.validateToken(token);

				if (!StringUtils.isBlank(bankIdFrmToken)) {
					bankId = jsonReq.getString("bankId");
					if (!bankId.equals(bankIdFrmToken)) {
						response.setMessageCode(Constants.STATUS_FAILED);
						response.setMessage("Incorrect Bank Id");
						response.setId(transId.toString());
						response.setStatus(Status.UNAUTHORIZED);
						return encResponse( response);
					}

					if (!jsonReq.has("bankId") || bankId.isEmpty()) {
						response.setMessageCode(Constants.STATUS_FAILED);
						response.setMessage(Constants.MISSING_BANKID);
						response.setStatus(Status.OK);
						return encResponse( response);
					//	return Response.status(Status.OK).entity(response).build();

					} else if (jsonReq.getString("bankId").length() > 50) {
						response.setMessageCode(Constants.STATUS_FAILED);
						response.setMessage(Constants.BANKID_SIZE);
						response.setStatus(Status.OK);
						return encResponse( response);
					}

					if (!jsonReq.has("transactionDate") || jsonReq.getString("transactionDate").isEmpty()) {
						response.setMessageCode(Constants.STATUS_FAILED);
						response.setMessage(Constants.MISSING_TRNDATE);
						response.setStatus(Status.OK);
						return encResponse( response);
					}

					if (!jsonReq.has("openingBalance") || jsonReq.getString("openingBalance").isEmpty()) {
						response.setMessageCode(Constants.STATUS_FAILED);
						response.setMessage(Constants.MISSING_OPENBAL);
						response.setStatus(Status.OK);
						return encResponse( response);
					}

					if (!jsonReq.has("closingBalance") || jsonReq.getString("closingBalance").isEmpty()) {
						response.setMessageCode(Constants.STATUS_FAILED);
						response.setMessage(Constants.MISSING_CLOSEBAL);
						response.setStatus(Status.OK);
						return encResponse( response);
					}

					JSONArray jsonArray1 = null;
					JSONArray jsonArray2 = null;
					try {
						jsonArray1 = jsonReq.getJSONArray("transactionDebits");

					} catch (Exception e) {

					}

					try {

						jsonArray2 = jsonReq.getJSONArray("transactionCredits");
					} catch (Exception e) {

					}

					if (jsonArray1 != null && jsonArray1.length() > 0) {
						for (int i = 0; i < jsonArray1.length(); i++) {

							jsonReq = jsonArray1.getJSONObject(i);
							response = CommonUtils.validateTransDebits(jsonReq);
							response.setId(transId.toString());

							if (StringUtils.isNotBlank(response.getMessageCode())) {
								response.setStatus(Status.OK);
								return encResponse( response);
							}
						}
					} else {
						response.setId(transId.toString());
						response.setMessageCode(Constants.STATUS_FAILED);
						response.setMessage(Constants.MISSING_TRNDEBIT_ARRAY);
						response.setStatus(Status.BAD_REQUEST);
						return encResponse( response);
					}

					if (jsonArray2 != null && jsonArray2.length() > 0) {
						for (int i = 0; i < jsonArray2.length(); i++) {

							jsonReq = jsonArray2.getJSONObject(i);
							response = CommonUtils.validateTransCredits(jsonReq);
							response.setId(transId.toString());

							if (StringUtils.isNotBlank(response.getMessageCode())) {
								response.setStatus(Status.OK);
								return encResponse( response);
							}
						}
					} else {
						response.setId(transId.toString());
						response.setMessageCode(Constants.STATUS_FAILED);
						response.setMessage(Constants.MISSING_TRNCREDIT_ARRAY);
						response.setStatus(Status.BAD_REQUEST);
						return encResponse( response);
					}

					// LOGIC FOR SAVING DATA

					reconcileDetails.setTransactionId(transId);
					response = bankAuthDao.postReconcileData(reconcileDetails);
					writeFileData(null, response, "ReconcileDetails_", "/reconcileDetails", null, jsonString, bankId,
							response.getId());
					response.setStatus(Status.OK);
					return encResponse( response);

				} else {
					
					response.setMessageCode(Constants.STATUS_FAILED);
					response.setMessage("Invalid Token");
					response.setId(transId.toString());
					response.setStatus(Status.UNAUTHORIZED);
					return encResponse( response);
				}
			} else {

				response.setMessageCode(Constants.STATUS_FAILED);
				response.setMessage("Please provide Token");
				response.setId(transId.toString());
				response.setStatus(Status.UNAUTHORIZED);
				return encResponse( response);
			}

		} catch (Exception e) {
		logger.error(e.toString());
			e.printStackTrace();
			response.setMessageCode(Constants.STATUS_FAILED);
			response.setMessage("Internal Server Error");
			response.setId(transId.toString());
			response.setStatus(Status.INTERNAL_SERVER_ERROR);
			return encResponse( response);
		} 
	}
	
	
	
	@PostMapping("/refundtransdetail")
	public ReqResDTO postRefundTransDetail(@RequestHeader("Authorization") String authorizationHeader,
			@RequestBody ReqResDTO reqDTO, HttpServletRequest request) throws Exception  {
		List<RefundDetails> refundDetails=null;
		JSONObject jsonReq =null;
		JSONObject payload=null; 
		ResponseDTO response = new ResponseDTO();
		String encData=reqDTO.getData();
		String encSessionKey=reqDTO.getSessionKey();
		String decSessionKey=encdec.decryptRSA(encSessionKey, privateKeyPath);
		String decData=encdec.decryptAES(encData, decSessionKey);
		BankAuthenticationDAO bankAuthDao = new BankAuthenticationDAO();
		String token = authorizationHeader.substring("Bearer".length()).trim();
		ObjectMapper objectMapper = new ObjectMapper();
//		 try {
//			 refundDetails = objectMapper.readValue(decData, new TypeReference<List<RefundDetails>>() {});
//			logger.info(refundDetails.toString());
//	        } catch (Exception e) {
//	            e.printStackTrace();
//	        }
		if (!payload.has("refundDetails") || payload.getJSONObject("refundDetails").isEmpty()) {
			response.setMessageCode(Constants.STATUS_FAILED);
			response.setMessage("missing refundDetails");
			response.setStatus(Status.OK);
			return encResponse(response);
		}
		if (!payload.has("hash") || payload.getString("hash").isEmpty()) {
			response.setMessageCode(Constants.STATUS_FAILED);
			response.setMessage("missing signature");
			response.setStatus(Status.OK);
			return encResponse(response);
		}
		JsonNode jsonNode = objectMapper.readTree(decData);
		JsonNode reconcileDetailsNode = jsonNode.get("refundDetails");
//	    JsonArray settlementRejCanListArray = payloadGson.getAsJsonObject("reconcileDetails")
//	            .getAsJsonArray("transactionDebits");
	  //  String details=settlementRejCanListArray.toString();
	 //   String data="{\"settlementStatusList\":"+details+"}";
	     jsonReq = payload.getJSONObject("refundDetails");
		 String signature = payload.getString("hash");
		 System.out.println("signature  :" +signature);
		 boolean isSignVerified=encdec.verifySign(reconcileDetailsNode.toString(), signature, publicKeyPath);
		 System.out.println("result  :" +isSignVerified);
		if(isSignVerified == false) {
			response.setMessageCode(Constants.STATUS_FAILED);
			response.setMessage("Inavlid signature");
			response.setStatus(Status.OK);
			return encResponse(response);

		}
		Date today = new Date((new java.util.Date()).getTime());
		Long transId = CommonDAO.getMaxNoInternal(Constants.CHAR_1, "RESTREADTRANSID", today, Constants.CHAR_1);

		try {
			Gson gson = new Gson();
			//String jsonString = gson.toJson(refundDetails);
		    jsonReq = new JSONObject("refundDetails");
			JSONArray jsonArray = payload.getJSONArray("refundList");

			if (jsonArray != null && jsonArray.length() > 0) {
				for (int i = 0; i < jsonArray.length(); i++) {

					jsonReq = jsonArray.getJSONObject(i);
					response = CommonUtils.validateRefundDetails(jsonReq);
					response.setId(transId.toString());

					if (StringUtils.isNotBlank(response.getMessageCode())) {
						response.setStatus(Status.OK);
						return encResponse(response);
					}
				}
			}

			List<String> bankIds = bankAuthDao.fetchBankIds(refundDetails);

			if (!StringUtils.isBlank(token)) {
				String bankIdFrmToken = bankAuthDao.validateToken(token);

				if (!StringUtils.isBlank(bankIdFrmToken)) {

					for (String bankId : bankIds) {
						if (!bankId.equals(bankIdFrmToken)) {
							response.setMessageCode(Constants.STATUS_FAILED);
							response.setMessage("Incorrect Bank Id");
							response.setId(transId.toString());
							response.setStatus(Status.UNAUTHORIZED);
							return encResponse(response);
						}
					}
					response = bankAuthDao.postRefundTransData(refundDetails, transId);
					writeFileData(jsonArray, response, "RefundDetail_", "/refundtransdetail", null, null,
							bankIds.get(0), response.getId());
					response.setStatus(Status.OK);
					return encResponse(response);

				} else {
					response.setMessageCode(Constants.STATUS_FAILED);
					response.setMessage("Invalid Token");
					response.setId(transId.toString());
					response.setStatus(Status.UNAUTHORIZED);
					return encResponse(response);
				}
			} else {

				response.setMessageCode(Constants.STATUS_FAILED);
				response.setMessage("Please provide Token");
				response.setId(transId.toString());
				response.setStatus(Status.UNAUTHORIZED);
				return encResponse(response);
			}
		} catch (Exception e) {
			e.printStackTrace();
			logger.error(e.toString());
			response.setMessageCode(Constants.STATUS_FAILED);
			response.setMessage("Internal Server Error");
			response.setId(transId.toString());
			response.setStatus(Status.INTERNAL_SERVER_ERROR);
			return encResponse(response);
		}
	}
	
	@PostMapping("/encryption")
	public ReqResDTO encTest(@RequestBody String jsonString) throws Exception {
		String randKey= encdec.getAlphaNumericString(10);
		System.out.println( " randKey : " +randKey);
		String encData=encdec.encryptAES(jsonString,randKey);
		System.out.println( " data : " +encData);
		String encKey=encdec.encryptRSA(randKey, publicKeyPath);
		System.out.println( " encKey : " +encKey);
		ReqResDTO reqResDTO= new ReqResDTO();
		reqResDTO.setData(encData);
		reqResDTO.setSessionKey(encKey);
		return reqResDTO;
		
	}
	
	@PostMapping("/decryption")
	public String decTest(@RequestBody ReqResDTO reqResDTO) throws Exception {
		System.out.println(reqResDTO.toString());
		String decSessionKey=encdec.decryptRSA(reqResDTO.getSessionKey(), privateKeyPath);
		String decData=encdec.decryptAES(reqResDTO.getData(), decSessionKey);
		System.out.println( " decData : " +decData);
		
		return decData;
		
	}
	@PostMapping("/generatesign")
	public String generatesign(@RequestBody Map<String, Object> signature) throws Exception {
		ObjectMapper objectMapper = new ObjectMapper();
	    String jsonString = objectMapper.writeValueAsString(signature);
		System.out.println(jsonString.toString());
		String sign=encdec.generateSign(jsonString.toString(), privateKeyPath);
		System.out.println( " sign : " +sign);
		
		return sign;
		
	}
	@PostMapping("/signtest")
	public boolean signtest(@RequestBody Map<String, Object> signature) throws Exception {
		System.out.println("data : " +signature.toString());
		String sign=encdec.generateSign(signature.toString(), privateKeyPath);
		System.out.println( " sign : " +sign);
		boolean result=encdec.verifySign(signature.toString(), sign, publicKeyPath);
		System.out.println( " result : " +result);
		return result;
		
	}
	
	private void writeFileData(JSONArray jsonArray, ResponseDTO response, String fileName, String endPoint,
			List<ResponseDTO> responseList, String jsonReq, String bankId, String transId)
			throws IntegrationsException {

		BankAuthenticationDAO bankAuthDao = new BankAuthenticationDAO();
		Boolean isLoggingEnable = Boolean.valueOf(bankAuthDao.getSysParamValue("202007211"));

		logger.info("Logging Enable Status =" + isLoggingEnable);

		if (isLoggingEnable) {
			String path = bankAuthDao.getSysParamValue("202007201");
			// String path = "D:/ENAM/apache-tomcat-8.5.55/webapps/bankapireqresplog";
			// String filePath1 = "/opt/tomcat8.5/apache/webapps/bankapireqresplog";

			File directory = new File(path + "/" + bankId);
			boolean success = directory.exists() ? true : directory.mkdir();
			String filePath = directory + "/";
			logger.info("Log file Path=" + filePath + " Path available=" + success);

			try (FileWriter file = new FileWriter(filePath + fileName.concat(transId) + "D"
					+ CommonUtils.getDateTime().replace(":", "").replace("_", "T") + ".log")) {
				file.write("Endpoint : " + endPoint + "\n");

				if (jsonReq == null) {
					file.append("Request : " + jsonArray.toString() + "\n");
				} else {
					file.append("Request : " + jsonReq + "\n");
				}

				if (responseList == null) {
					file.append("Response : " + response + "\n");
				} else {
					file.append("Response : " + responseList + "\n");
				}

				file.append("======================Endpoint processed======================");
				file.flush();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
//Decrypt response;
	public ReqResDTO encResponse(ResponseDTO response) throws Exception {
		String randomKey=encdec.getAlphaNumericString(10);
		String encData=encdec.encryptAES(response.toString(), randomKey);
		String sessionKey=encdec.encryptRSA(randomKey, publicKeyPath);
		ReqResDTO reqResDTO= new ReqResDTO();
		reqResDTO.setData(encData);
		reqResDTO.setSessionKey(sessionKey);
		
		return reqResDTO;
		
	}
	
}
